"""
Tests for threat recommendations engine module.
"""

import os
import json
import pytest
from src.recommendation_config import RecommendationConfig
from src.threat_recommendations import (
    evaluate_all_rules,
    generate_recommendation_report,
    load_analytics_evidence,
    run_all_threat_recommendations,
    validate_evidence_bundle,
)


def test_load_real_analytics_evidence():
    for m_type in ["10_features", "20_features"]:
        bundle = load_analytics_evidence(m_type)
        assert bundle["model_type"] == m_type
        assert len(bundle["loaded_files"]) == 9
        assert len(bundle["missing_files"]) == 0
        assert bundle["total_cases"]["valid_phishing_records"] == 4898

        is_valid, issues = validate_evidence_bundle(bundle, m_type)
        assert is_valid is True
        assert issues == []


def test_evaluate_all_rules_real_data():
    for m_type in ["10_features", "20_features"]:
        bundle = load_analytics_evidence(m_type)
        res = evaluate_all_rules(bundle, model_type=m_type)

        assert res["model_type"] == m_type
        assert res["evaluation_summary"]["total_rules_evaluated"] == 20
        # Exactly 19 rules trigger; Rule 19 has insufficient evidence due to absence of historical event timestamps
        assert res["evaluation_summary"]["triggered_count"] == 19
        assert res["evaluation_summary"]["insufficient_evidence_count"] == 1
        assert res["evaluation_summary"]["active_recommendations_count"] == 19

        # Ensure active recommendations are sorted by priority (high then medium then low)
        priorities = [r["priority"] for r in res["active_recommendations"]]
        assert priorities[0] == "high"


def test_generate_report_end_to_end(tmp_path):
    out_dir = str(tmp_path / "threat_recommendations")
    res = generate_recommendation_report(
        model_type="10_features",
        output_base_dir=out_dir,
    )

    out_file = res["output_file"]
    assert os.path.exists(out_file)

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["model_type"] == "10_features"
    assert len(data["active_recommendations"]) == 19
    assert len(data["rule_evaluation_audit"]) == 20


def test_evidence_bundle_mismatch_validation():
    bundle = load_analytics_evidence("10_features")
    # Evaluating 10-feature bundle as 20_features should fail validation
    is_valid, issues = validate_evidence_bundle(bundle, "20_features")
    assert is_valid is False
    assert any("model_type_mismatch" in iss for iss in issues)
