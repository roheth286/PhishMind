"""
Tests for threat intelligence analytics engine.
"""

import os
import pytest
from src.threat_analytics import (
    compute_feature_cooccurrence,
    compute_feature_statistics,
    compute_top_signals,
    compute_total_cases,
    detect_unusual_patterns,
    generate_recommendation_evidence,
    generate_threat_analytics_report,
)


def test_compute_total_cases():
    records = [
        {"id": "1", "vector": [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},
        {"id": "2", "vector": [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},  # duplicate of 1
        {"id": "3", "vector": [1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},
    ]
    res = compute_total_cases(records, "10_features", invalid_count=1)
    assert res["total_records_stored"] == 4
    assert res["valid_phishing_records"] == 3
    assert res["invalid_records_count"] == 1
    assert res["distinct_vector_patterns"] == 2
    assert res["duplicate_vector_count"] == 1


def test_compute_feature_statistics_and_top_signals():
    records = [
        {"id": "1", "vector": [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},
        {"id": "2", "vector": [-1, -1, 1, 1, -1, 1, -1, 1, 1, 0]},
    ]
    stats = compute_feature_statistics(records, "10_features")
    assert "having_IP_Address" in stats
    assert stats["having_IP_Address"]["counts"]["-1"] == 2
    assert stats["having_IP_Address"]["percentages"]["-1"] == 100.0
    assert stats["having_IP_Address"]["is_uniform"] is True

    signals = compute_top_signals(stats, "10_features", top_n=5)
    assert len(signals) == 5
    # The first signal should have 100% frequency
    assert signals[0]["percentage"] == 100.0


def test_detect_unusual_patterns():
    # 9 instances of pattern A, 1 instance of pattern B
    pat_a = [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]
    pat_b = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    records = [{"id": f"a_{i}", "vector": pat_a} for i in range(9)]
    records.append({"id": "b_0", "vector": pat_b})

    res = detect_unusual_patterns(records, "10_features", rarity_count_threshold=1)
    assert res["rare_pattern_count"] == 1
    assert res["rare_sample_count"] == 1
    assert res["rare_patterns"][0]["vector"] == pat_b


def test_compute_feature_cooccurrence():
    records = [
        {"id": "1", "vector": [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},
        {"id": "2", "vector": [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]},
        {"id": "3", "vector": [-1, -1, 1, 1, -1, 1, -1, 1, 1, 0]},
    ]
    cooccur = compute_feature_cooccurrence(records, "10_features", min_support=0.3)
    assert cooccur["total_records"] == 3
    assert cooccur["top_pairs_count"] > 0
    # Every pair that has 100% cooccurrence should have support 1.0
    top_pair = cooccur["top_cooccurrences"][0]
    assert "support" in top_pair
    assert "confidence_A_to_B" in top_pair


def test_generate_threat_analytics_report_file_creation(tmp_path):
    report_dir = str(tmp_path / "reports")
    res = generate_threat_analytics_report(
        model_type="10_features",
        reports_dir=report_dir,
        n_clusters=3,
    )
    assert res["model_type"] == "10_features"
    subfolder = os.path.join(report_dir, "phishing_10_features")
    expected_files = [
        "summary.json",
        "data_quality.json",
        "feature_statistics.json",
        "top_signals.json",
        "clustering.json",
        "cluster_profiles.json",
        "unusual_patterns.json",
        "feature_cooccurrence.json",
        "recommendation_evidence.json",
    ]
    for ef in expected_files:
        assert os.path.exists(os.path.join(subfolder, ef))
