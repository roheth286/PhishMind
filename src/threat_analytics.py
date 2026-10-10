"""
Threat Intelligence Analytics Module.

Performs standalone analytical discovery, pattern mining, and statistical profiling
over historical phishing vectors stored in ChromaDB collections ('phishing_10_features'
and 'phishing_20_features').

Responsibilities:
- Total cases summary (total, valid, invalid, distinct, duplicate).
- Feature value frequencies and percentages (-1, 0, 1).
- Ranked top common feature signals with deterministic tie-breaking.
- Clustering analysis and profiling (via src.threat_clustering).
- Unusual / rare pattern detection.
- Feature co-occurrence matrix (pair counts, support, directional confidence).
- Evidence summary formatted for downstream rule-based recommendation engines.
- Standalone multi-file JSON report persistence to 'reports/threat_analytics/'.
- Strict separation of 10-feature and 20-feature analytics.
- Strict non-fabrication of historical time trends (observed_at explicitly disclosed).
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from src.threat_clustering import (
    analyze_cluster_sizes,
    discover_clusters,
    profile_clusters,
)
from src.threat_data_quality import audit_collection_data_quality
from src.threat_vector_db import (
    FEATURES_10,
    FEATURES_20,
    MODEL_TYPE_TO_COLLECTION,
    validate_model_type,
)


def compute_total_cases(
    records: List[Dict[str, Any]],
    model_type: str,
    invalid_count: int = 0,
) -> Dict[str, Any]:
    """
    Compute total stored phishing case metrics.
    """
    validate_model_type(model_type)
    valid_count = len(records)
    total_count = valid_count + invalid_count

    vectors = [r["vector"] for r in records]
    vector_tuples = [tuple(v) for v in vectors]
    distinct_count = len(set(vector_tuples))
    duplicate_count = valid_count - distinct_count

    return {
        "model_type": model_type,
        "total_records_stored": total_count,
        "valid_phishing_records": valid_count,
        "invalid_records_count": invalid_count,
        "distinct_vector_patterns": distinct_count,
        "duplicate_vector_count": duplicate_count,
        "duplicate_rate_percentage": round((duplicate_count / valid_count * 100.0), 4) if valid_count > 0 else 0.0,
    }


def compute_feature_statistics(
    records: List[Dict[str, Any]],
    model_type: str,
) -> Dict[str, Any]:
    """
    Compute per-feature value counts (-1, 0, 1) and percentages across all valid records.
    """
    validate_model_type(model_type)
    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    n_samples = len(records)

    feature_stats: Dict[str, Any] = {}

    for f_idx, feat_name in enumerate(expected_features):
        counts = {-1: 0, 0: 0, 1: 0}
        for rec in records:
            vec = rec["vector"]
            if f_idx < len(vec):
                val = vec[f_idx]
                if val in counts:
                    counts[val] += 1
                else:
                    counts[val] = 1

        percentages = {}
        for val, cnt in counts.items():
            percentages[str(val)] = round((cnt / n_samples * 100.0), 4) if n_samples > 0 else 0.0

        # Dominant value(s)
        max_cnt = max(counts.values()) if counts else 0
        dominant = [v for v in [-1, 0, 1] if counts.get(v, 0) == max_cnt]

        feature_stats[feat_name] = {
            "feature_name": feat_name,
            "feature_index": f_idx,
            "counts": {str(k): v for k, v in counts.items()},
            "percentages": percentages,
            "dominant_values": dominant,
            "is_uniform": (max_cnt == n_samples and n_samples > 0),
        }

    return feature_stats


def compute_top_signals(
    feature_stats: Dict[str, Any],
    model_type: str,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Rank top common feature signals observed in phishing records.
    
    A signal is a specific feature-value condition (e.g. "Prefix_Suffix == -1").
    Ranked deterministically by:
      1. count (descending)
      2. percentage (descending)
      3. feature_name (alphabetical ascending)
      4. feature_value (ascending)
    """
    validate_model_type(model_type)
    all_signals: List[Dict[str, Any]] = []

    for feat_name, stats in feature_stats.items():
        counts = stats["counts"]
        percentages = stats["percentages"]
        for val_str, cnt in counts.items():
            val_int = int(val_str)
            pct = percentages[val_str]
            all_signals.append({
                "feature_name": feat_name,
                "feature_value": val_int,
                "signal_name": f"{feat_name} == {val_int}",
                "count": cnt,
                "percentage": pct,
            })

    # Deterministic sorting
    sorted_signals = sorted(
        all_signals,
        key=lambda s: (-s["count"], -s["percentage"], s["feature_name"], s["feature_value"]),
    )

    return sorted_signals[:top_n]


def detect_unusual_patterns(
    records: List[Dict[str, Any]],
    model_type: str,
    rarity_count_threshold: int = 2,
    rarity_percentage_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Detect unusual / rare vector combinations in the stored phishing dataset.
    
    A pattern is considered rare if its occurrence count <= rarity_count_threshold
    OR if its percentage of the total valid dataset <= rarity_percentage_threshold (if specified).
    """
    validate_model_type(model_type)
    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    n_samples = len(records)

    if n_samples == 0:
        return {
            "model_type": model_type,
            "total_samples": 0,
            "total_distinct_patterns": 0,
            "rarity_count_threshold": rarity_count_threshold,
            "rarity_percentage_threshold": rarity_percentage_threshold,
            "rare_pattern_count": 0,
            "rare_sample_count": 0,
            "rare_patterns": [],
        }

    # Count frequencies of distinct vector tuples
    pattern_counter: Counter = Counter()
    pattern_sample_ids: Dict[Tuple[int, ...], List[str]] = {}

    for rec in records:
        vec_tuple = tuple(rec["vector"])
        pattern_counter[vec_tuple] += 1
        if vec_tuple not in pattern_sample_ids:
            pattern_sample_ids[vec_tuple] = []
        pattern_sample_ids[vec_tuple].append(rec["id"])

    rare_patterns: List[Dict[str, Any]] = []
    rare_sample_count = 0

    for vec_tuple, cnt in pattern_counter.items():
        pct = round((cnt / n_samples * 100.0), 4)
        is_rare = False

        if cnt <= rarity_count_threshold:
            is_rare = True
        elif rarity_percentage_threshold is not None and pct <= rarity_percentage_threshold:
            is_rare = True

        if is_rare:
            rare_sample_count += cnt
            pattern_dict = {expected_features[i]: vec_tuple[i] for i in range(len(vec_tuple))}
            rare_patterns.append({
                "vector": list(vec_tuple),
                "pattern_dict": pattern_dict,
                "count": cnt,
                "percentage": pct,
                "sample_ids": pattern_sample_ids[vec_tuple][:5],  # sample up to 5 IDs
            })

    # Sort rare patterns deterministically: count asc, then vector representation
    rare_patterns_sorted = sorted(
        rare_patterns,
        key=lambda p: (p["count"], p["percentage"], str(p["vector"])),
    )

    return {
        "model_type": model_type,
        "total_samples": n_samples,
        "total_distinct_patterns": len(pattern_counter),
        "rarity_count_threshold": rarity_count_threshold,
        "rarity_percentage_threshold": rarity_percentage_threshold,
        "rare_pattern_count": len(rare_patterns_sorted),
        "rare_sample_count": rare_sample_count,
        "rare_sample_percentage": round((rare_sample_count / n_samples * 100.0), 4) if n_samples > 0 else 0.0,
        "rare_patterns": rare_patterns_sorted,
    }


def compute_feature_cooccurrence(
    records: List[Dict[str, Any]],
    model_type: str,
    target_values: Tuple[int, ...] = (-1, 1),
    min_support: float = 0.10,
    top_n: int = 50,
) -> Dict[str, Any]:
    """
    Compute pairwise feature co-occurrence statistics across all valid records.
    
    For pairs of conditions (A, B) such as (feat_A == val_A, feat_B == val_B):
    - count: number of records satisfying both A and B
    - support: P(A and B) = count / total_records
    - confidence_A_to_B: P(B | A) = count(A and B) / count(A)
    - confidence_B_to_A: P(A | B) = count(A and B) / count(B)
    """
    validate_model_type(model_type)
    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    n_samples = len(records)

    if n_samples == 0:
        return {
            "model_type": model_type,
            "total_records": 0,
            "min_support": min_support,
            "top_pairs_count": 0,
            "top_cooccurrences": [],
        }

    # Count single occurrences: condition -> count
    # Condition tuple: (feat_name, val)
    single_counts: Dict[Tuple[str, int], int] = {}
    for feat_name in expected_features:
        for val in target_values:
            single_counts[(feat_name, val)] = 0

    for rec in records:
        vec = rec["vector"]
        for f_idx, feat_name in enumerate(expected_features):
            val = vec[f_idx]
            if val in target_values:
                key = (feat_name, val)
                single_counts[key] = single_counts.get(key, 0) + 1

    # Count pair co-occurrences
    pair_counts: Dict[Tuple[Tuple[str, int], Tuple[str, int]], int] = {}

    for rec in records:
        vec = rec["vector"]
        active_conditions: List[Tuple[str, int]] = []
        for f_idx, feat_name in enumerate(expected_features):
            val = vec[f_idx]
            if val in target_values:
                active_conditions.append((feat_name, val))

        # Pairwise combinations (ordered by feature index)
        num_cond = len(active_conditions)
        for i in range(num_cond):
            cond_a = active_conditions[i]
            for j in range(i + 1, num_cond):
                cond_b = active_conditions[j]
                pair_key = (cond_a, cond_b)
                pair_counts[pair_key] = pair_counts.get(pair_key, 0) + 1

    # Format co-occurrences
    results: List[Dict[str, Any]] = []

    for (cond_a, cond_b), joint_cnt in pair_counts.items():
        support = joint_cnt / n_samples
        if support < min_support:
            continue

        cnt_a = single_counts.get(cond_a, 0)
        cnt_b = single_counts.get(cond_b, 0)

        conf_a_to_b = (joint_cnt / cnt_a) if cnt_a > 0 else 0.0
        conf_b_to_a = (joint_cnt / cnt_b) if cnt_b > 0 else 0.0

        results.append({
            "feature_A": cond_a[0],
            "value_A": cond_a[1],
            "condition_A": f"{cond_a[0]} == {cond_a[1]}",
            "feature_B": cond_b[0],
            "value_B": cond_b[1],
            "condition_B": f"{cond_b[0]} == {cond_b[1]}",
            "joint_count": joint_cnt,
            "support": round(support, 4),
            "support_percentage": round(support * 100.0, 4),
            "confidence_A_to_B": round(conf_a_to_b, 4),
            "confidence_B_to_A": round(conf_b_to_a, 4),
        })

    # Sort deterministically: joint_count desc, support desc, feature_A, feature_B
    results_sorted = sorted(
        results,
        key=lambda r: (-r["joint_count"], -r["support"], r["feature_A"], r["feature_B"]),
    )

    return {
        "model_type": model_type,
        "total_records": n_samples,
        "min_support": min_support,
        "top_pairs_count": len(results_sorted[:top_n]),
        "top_cooccurrences": results_sorted[:top_n],
    }


def generate_recommendation_evidence(
    model_type: str,
    total_cases: Dict[str, Any],
    top_signals: List[Dict[str, Any]],
    cluster_profiles: Dict[str, Any],
    unusual_patterns: Dict[str, Any],
    cooccurrence: Dict[str, Any],
    data_quality_report: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Format structured evidence summaries specifically structured for future
    rule-based recommendation engine consumption.
    """
    validate_model_type(model_type)

    # 1. High-frequency threat markers (signals present in >= 50% of phishing records)
    high_freq_markers = [
        {
            "signal": s["signal_name"],
            "feature": s["feature_name"],
            "value": s["feature_value"],
            "support_percentage": s["percentage"],
            "evidence_weight": "high" if s["percentage"] >= 75.0 else "medium",
        }
        for s in top_signals
        if s["percentage"] >= 50.0
    ]

    # 2. Strong co-occurrence rules (confidence >= 80% and support >= 25%)
    strong_correlations = []
    for pair in cooccurrence.get("top_cooccurrences", []):
        if pair["confidence_A_to_B"] >= 0.80 and pair["support_percentage"] >= 25.0:
            strong_correlations.append({
                "premise": pair["condition_A"],
                "implication": pair["condition_B"],
                "confidence": pair["confidence_A_to_B"],
                "support_percentage": pair["support_percentage"],
            })

    # 3. Archetype cluster indicators (uniform features in each cluster)
    archetype_signatures = {}
    for c_name, c_data in cluster_profiles.items():
        uniform_feats = {}
        for f_name, f_info in c_data["features"].items():
            if f_info["is_uniform"]:
                uniform_feats[f_name] = f_info["dominant_values"][0]

        archetype_signatures[c_name] = {
            "cluster_id": c_data["cluster_id"],
            "percentage_of_phishing_population": c_data["percentage_of_total"],
            "invariant_features": uniform_feats,
        }

    return {
        "model_type": model_type,
        "generation_timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_purpose": "Inputs for future rule-based recommendation engine",
        "dataset_foundation": {
            "total_phishing_cases_analyzed": total_cases.get("valid_phishing_records", 0),
            "distinct_archetype_vectors": total_cases.get("distinct_vector_patterns", 0),
            "data_quality_certified": data_quality_report.get("status") == "complete",
        },
        "high_frequency_threat_markers": high_freq_markers,
        "strong_feature_implications": strong_correlations[:15],
        "cluster_archetype_signatures": archetype_signatures,
        "rare_variant_heuristics": {
            "total_rare_variants_cataloged": unusual_patterns.get("rare_pattern_count", 0),
            "rare_variant_population_share_pct": unusual_patterns.get("rare_sample_percentage", 0.0),
        },
    }


def generate_threat_analytics_report(
    model_type: str,
    persist_dir: Optional[str] = None,
    reports_dir: str = "reports/threat_analytics",
    n_clusters: Optional[int] = None,
    rarity_count_threshold: int = 2,
    rarity_percentage_threshold: Optional[float] = None,
    min_support: float = 0.10,
) -> Dict[str, Any]:
    """
    Execute full analytics pipeline for the specified model_type and save all 9 reports.
    """
    validate_model_type(model_type)
    subfolder_name = "phishing_10_features" if model_type == "10_features" else "phishing_20_features"
    target_dir = os.path.join(reports_dir, subfolder_name)
    os.makedirs(target_dir, exist_ok=True)

    # 1. Audit Data Quality and Fetch Valid Records
    dq_report, valid_records = audit_collection_data_quality(model_type, persist_dir=persist_dir)
    invalid_count = dq_report.get("invalid_records_count", 0)

    # 2. Total Cases Summary
    total_cases = compute_total_cases(valid_records, model_type, invalid_count=invalid_count)

    # 3. Feature Statistics
    feature_stats = compute_feature_statistics(valid_records, model_type)

    # 4. Top Signals
    top_signals = compute_top_signals(feature_stats, model_type, top_n=15)

    # 5. Clustering
    vectors = [r["vector"] for r in valid_records]
    record_ids = [r["id"] for r in valid_records]
    clustering_res = discover_clusters(
        model_type=model_type,
        vectors=vectors,
        record_ids=record_ids,
        n_clusters=n_clusters,
        random_state=42,
    )
    cluster_sizes = analyze_cluster_sizes(clustering_res, vectors)
    cluster_profiles = profile_clusters(clustering_res, vectors, model_type)

    clustering_report = {
        "model_type": model_type,
        "algorithm": clustering_res["algorithm"],
        "distance_metric": clustering_res["distance_metric"],
        "random_state": clustering_res["random_state"],
        "n_clusters": clustering_res["n_clusters"],
        "inertia": clustering_res["inertia"],
        "silhouette_score": clustering_res["silhouette_score"],
        "status": clustering_res["status"],
        "rationale": clustering_res["rationale"],
        "cluster_sizes": cluster_sizes,
    }

    # 6. Unusual Patterns
    unusual_patterns = detect_unusual_patterns(
        valid_records,
        model_type,
        rarity_count_threshold=rarity_count_threshold,
        rarity_percentage_threshold=rarity_percentage_threshold,
    )

    # 7. Co-occurrence
    cooccurrence = compute_feature_cooccurrence(
        valid_records,
        model_type,
        min_support=min_support,
        top_n=40,
    )

    # 8. Recommendation Evidence
    rec_evidence = generate_recommendation_evidence(
        model_type,
        total_cases,
        top_signals,
        cluster_profiles,
        unusual_patterns,
        cooccurrence,
        dq_report,
    )

    # 9. Top-Level Summary
    summary_report = {
        "model_type": model_type,
        "collection_name": MODEL_TYPE_TO_COLLECTION[model_type],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_cases_summary": total_cases,
        "data_quality_summary": {
            "status": dq_report["status"],
            "quality_percentage": dq_report.get("data_quality_percentage", 100.0),
            "invalid_records_count": dq_report.get("invalid_records_count", 0),
        },
        "clustering_summary": {
            "algorithm": clustering_res["algorithm"],
            "n_clusters": clustering_res["n_clusters"],
            "silhouette_score": clustering_res["silhouette_score"],
            "cluster_distribution": [
                {"cluster_id": cs["cluster_id"], "size": cs["member_count"], "percentage": cs["percentage"]}
                for cs in cluster_sizes
            ],
        },
        "unusual_patterns_summary": {
            "rare_pattern_count": unusual_patterns["rare_pattern_count"],
            "rare_sample_count": unusual_patterns["rare_sample_count"],
            "rare_sample_percentage": unusual_patterns["rare_sample_percentage"],
        },
        "top_5_signals": top_signals[:5],
        "timestamp_handling_disclosure": {
            "historical_time_trends_available": False,
            "observed_at_semantics": (
                "The 'observed_at' metadata field records database batch import timestamp. "
                "The source phishing dataset does not contain historical incident event dates. "
                "Time trend analytics are accurately reported as unavailable without fabricating temporal distributions."
            ),
        },
    }

    # Write all 9 JSON files
    reports_map = {
        "summary.json": summary_report,
        "data_quality.json": dq_report,
        "feature_statistics.json": feature_stats,
        "top_signals.json": top_signals,
        "clustering.json": clustering_report,
        "cluster_profiles.json": cluster_profiles,
        "unusual_patterns.json": unusual_patterns,
        "feature_cooccurrence.json": cooccurrence,
        "recommendation_evidence.json": rec_evidence,
    }

    for filename, data in reports_map.items():
        filepath = os.path.join(target_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return {
        "model_type": model_type,
        "output_directory": target_dir,
        "reports_generated": list(reports_map.keys()),
        "summary": summary_report,
    }


def run_full_threat_analytics(
    persist_dir: Optional[str] = None,
    reports_dir: str = "reports/threat_analytics",
) -> Dict[str, Any]:
    """
    Run full threat analytics across both 10-feature and 20-feature collections
    and write all standalone reports.
    """
    res_10 = generate_threat_analytics_report(
        model_type="10_features",
        persist_dir=persist_dir,
        reports_dir=reports_dir,
        n_clusters=4,  # Optimal silhouette score
    )
    res_20 = generate_threat_analytics_report(
        model_type="20_features",
        persist_dir=persist_dir,
        reports_dir=reports_dir,
        n_clusters=4,
    )

    return {
        "status": "success",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "10_features": res_10,
        "20_features": res_20,
    }


if __name__ == "__main__":
    print("Running standalone threat intelligence analytics...")
    results = run_full_threat_analytics()
    print("Threat analytics completed successfully!")
    print(f"10-Feature Report Dir: {results['10_features']['output_directory']}")
    print(f"20-Feature Report Dir: {results['20_features']['output_directory']}")
