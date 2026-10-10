"""
Threat Recommendations Engine Module.

Coordinates rule evaluation, evidence validation, deduplication, report generation,
and machine-readable persistence for the 20 threat intelligence rules.

Provides:
- load_analytics_evidence(model_type, reports_base_dir)
- validate_evidence_bundle(analytics_bundle, model_type)
- evaluate_all_rules(analytics_bundle, config, model_type)
- generate_recommendation_report(model_type, reports_base_dir, output_dir, config)
- run_all_threat_recommendations(reports_base_dir, output_dir, config)
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.recommendation_config import DEFAULT_RECOMMENDATION_CONFIG, RecommendationConfig
from src.recommendation_rules import ALL_RULES
from src.threat_vector_db import (
    FEATURES_10,
    FEATURES_20,
    MODEL_TYPE_TO_COLLECTION,
    validate_model_type,
)


def load_analytics_evidence(
    model_type: str,
    reports_base_dir: str = "reports/threat_analytics",
) -> Dict[str, Any]:
    """
    Safely load all Phase 2 analytics reports for the given model_type.
    Detects missing or malformed reports without crashing.
    """
    validate_model_type(model_type)
    subfolder = "phishing_10_features" if model_type == "10_features" else "phishing_20_features"
    target_dir = os.path.join(reports_base_dir, subfolder)

    files_to_load = {
        "summary": "summary.json",
        "data_quality": "data_quality.json",
        "feature_statistics": "feature_statistics.json",
        "top_signals": "top_signals.json",
        "clustering": "clustering.json",
        "cluster_profiles": "cluster_profiles.json",
        "unusual_patterns": "unusual_patterns.json",
        "feature_cooccurrence": "feature_cooccurrence.json",
        "recommendation_evidence": "recommendation_evidence.json",
    }

    bundle: Dict[str, Any] = {
        "model_type": model_type,
        "collection_name": MODEL_TYPE_TO_COLLECTION[model_type],
        "loaded_files": [],
        "missing_files": [],
    }

    for key, filename in files_to_load.items():
        filepath = os.path.join(target_dir, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    bundle[key] = json.load(f)
                    bundle["loaded_files"].append(filename)
            except Exception as e:
                bundle["missing_files"].append(f"{filename} (corrupted: {str(e)})")
                bundle[key] = None
        else:
            bundle["missing_files"].append(filename)
            bundle[key] = None

    # Convenience extract for total_cases
    if bundle.get("summary") and isinstance(bundle["summary"], dict):
        bundle["total_cases"] = bundle["summary"].get("total_cases_summary", {})
    else:
        bundle["total_cases"] = {}

    return bundle


def validate_evidence_bundle(
    analytics_bundle: Dict[str, Any],
    model_type: str,
) -> Tuple[bool, List[str]]:
    """
    Validate that an analytics evidence bundle is intact, internally consistent,
    and suitable for rule evaluation.
    """
    issues: List[str] = []

    if not isinstance(analytics_bundle, dict):
        return False, ["evidence_bundle_not_a_dictionary"]

    if analytics_bundle.get("model_type") != model_type:
        issues.append(f"model_type_mismatch: expected {model_type}, got {analytics_bundle.get('model_type')}")

    # Check for essential reports
    for req_key in ["summary", "feature_statistics", "clustering", "unusual_patterns"]:
        if analytics_bundle.get(req_key) is None:
            issues.append(f"missing_critical_report: {req_key}")

    # Check schema feature alignment
    expected_features = set(FEATURES_10 if model_type == "10_features" else FEATURES_20)
    feat_stats = analytics_bundle.get("feature_statistics")
    if isinstance(feat_stats, dict):
        present_features = set(feat_stats.keys())
        missing_feats = expected_features - present_features
        if missing_feats:
            issues.append(f"missing_expected_features: {sorted(list(missing_feats))}")

    # Check denominator consistency
    total_cases = analytics_bundle.get("total_cases", {})
    valid_count = total_cases.get("valid_phishing_records", 0)
    if valid_count <= 0:
        issues.append("invalid_or_zero_denominator_in_total_cases")

    # Check data quality status
    dq = analytics_bundle.get("data_quality", {})
    if dq and dq.get("status") not in ("complete", "partial_failures"):
        issues.append(f"unexpected_data_quality_status: {dq.get('status')}")

    is_valid = len(issues) == 0
    return is_valid, issues


def evaluate_all_rules(
    analytics_bundle: Dict[str, Any],
    config: Optional[RecommendationConfig] = None,
    model_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate all 20 recommendation rules against the provided evidence bundle.
    Returns:
        Dict containing active recommendations, audit evaluations, and metadata.
    """
    if config is None:
        config = DEFAULT_RECOMMENDATION_CONFIG

    if model_type is None:
        model_type = analytics_bundle.get("model_type", "10_features")

    validate_model_type(model_type)

    is_valid, validation_issues = validate_evidence_bundle(analytics_bundle, model_type)

    evaluated_rules: List[Dict[str, Any]] = []
    triggered_recommendations: List[Dict[str, Any]] = []
    insufficient_evidence_rules: List[Dict[str, Any]] = []
    not_triggered_rules: List[Dict[str, Any]] = []

    # Evaluate each registered rule
    for rule_func in ALL_RULES:
        try:
            res = rule_func(analytics_bundle, config, model_type)
        except Exception as e:
            res = {
                "recommendation_id": f"ERROR_{rule_func.__name__}_{model_type}",
                "rule_id": rule_func.__name__,
                "model_type": model_type,
                "title": "Rule evaluation error",
                "category": "Error",
                "recommendation": "Error occurred during rule evaluation.",
                "status": "error",
                "priority": "low",
                "priority_reason": "Execution error",
                "trigger_reason": str(e),
                "evidence": {},
                "thresholds": {},
                "limitations": [],
            }

        evaluated_rules.append(res)
        status = res.get("status")
        if status == "triggered":
            triggered_recommendations.append(res)
        elif status == "insufficient_evidence":
            insufficient_evidence_rules.append(res)
        elif status == "not_triggered":
            not_triggered_rules.append(res)

    # Sort triggered recommendations deterministically: Priority (high -> medium -> low), then rule_id
    priority_order = {"high": 0, "medium": 1, "low": 2}
    triggered_sorted = sorted(
        triggered_recommendations,
        key=lambda r: (priority_order.get(r.get("priority", "low"), 3), r.get("rule_id", "")),
    )

    # Apply deduplication / grouping if enabled
    final_active_recommendations = triggered_sorted[:config.max_active_recommendations]

    return {
        "model_type": model_type,
        "collection_name": MODEL_TYPE_TO_COLLECTION[model_type],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config_version": config.config_version,
        "evidence_validation": {
            "is_valid": is_valid,
            "issues": validation_issues,
            "loaded_files_count": len(analytics_bundle.get("loaded_files", [])),
            "missing_files_count": len(analytics_bundle.get("missing_files", [])),
        },
        "evaluation_summary": {
            "total_rules_evaluated": len(evaluated_rules),
            "triggered_count": len(triggered_recommendations),
            "not_triggered_count": len(not_triggered_rules),
            "insufficient_evidence_count": len(insufficient_evidence_rules),
            "active_recommendations_count": len(final_active_recommendations),
        },
        "active_recommendations": final_active_recommendations,
        "rule_evaluation_audit": evaluated_rules,
    }


def generate_recommendation_report(
    model_type: str,
    reports_base_dir: str = "reports/threat_analytics",
    output_base_dir: str = "reports/threat_recommendations",
    config: Optional[RecommendationConfig] = None,
) -> Dict[str, Any]:
    """
    End-to-end report generator for a specific model type.
    Loads Phase 2 analytics, evaluates all 20 rules, writes recommendations.json.
    """
    validate_model_type(model_type)
    if config is None:
        config = DEFAULT_RECOMMENDATION_CONFIG

    subfolder = "phishing_10_features" if model_type == "10_features" else "phishing_20_features"
    target_out_dir = os.path.join(output_base_dir, subfolder)
    os.makedirs(target_out_dir, exist_ok=True)

    bundle = load_analytics_evidence(model_type, reports_base_dir=reports_base_dir)
    report_dict = evaluate_all_rules(bundle, config=config, model_type=model_type)

    out_file = os.path.join(target_out_dir, "recommendations.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    return {
        "model_type": model_type,
        "output_file": out_file,
        "report": report_dict,
    }


def run_all_threat_recommendations(
    reports_base_dir: str = "reports/threat_analytics",
    output_base_dir: str = "reports/threat_recommendations",
    config: Optional[RecommendationConfig] = None,
) -> Dict[str, Any]:
    """
    Run threat recommendation engine across both 10-feature and 20-feature collections.
    """
    res_10 = generate_recommendation_report(
        model_type="10_features",
        reports_base_dir=reports_base_dir,
        output_base_dir=output_base_dir,
        config=config,
    )
    res_20 = generate_recommendation_report(
        model_type="20_features",
        reports_base_dir=reports_base_dir,
        output_base_dir=output_base_dir,
        config=config,
    )

    return {
        "status": "success",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "10_features": res_10,
        "20_features": res_20,
    }


if __name__ == "__main__":
    print("Evaluating standalone threat intelligence recommendation engine...")
    results = run_all_threat_recommendations()
    print("Recommendation generation complete!")
    print(f"10-Feature Report: {results['10_features']['output_file']}")
    print(f"20-Feature Report: {results['20_features']['output_file']}")
