"""
Tests for all 20 recommendation rules using synthetic and real evidence.
"""

import pytest
from src.recommendation_config import RecommendationConfig
from src.recommendation_rules import (
    ALL_RULES,
    evaluate_rule_1_shortened_url,
    evaluate_rule_2_ip_address_links,
    evaluate_rule_3_lookalike_domain,
    evaluate_rule_4_subdomain_review,
    evaluate_rule_5_https_validation,
    evaluate_rule_6_url_normalization,
    evaluate_rule_7_external_link_inspection,
    evaluate_rule_8_attachment_link_defense,
    evaluate_rule_9_sender_authentication,
    evaluate_rule_10_domain_reputation,
    evaluate_rule_11_outbound_web_access,
    evaluate_rule_12_security_awareness,
    evaluate_rule_13_lookalike_monitoring,
    evaluate_rule_14_safe_detonation,
    evaluate_rule_15_web_gateway_review,
    evaluate_rule_16_cluster_detection_rules,
    evaluate_rule_17_rare_pattern_investigation,
    evaluate_rule_18_layered_defenses,
    evaluate_rule_19_control_effectiveness,
    evaluate_rule_20_prioritize_strongest_evidence,
)


def _make_synthetic_bundle(total_count=1000):
    return {
        "model_type": "10_features",
        "total_cases": {"valid_phishing_records": total_count, "distinct_vector_patterns": 100},
        "feature_statistics": {
            "Shortining_Service": {"counts": {"-1": 150, "1": 850}, "percentages": {"-1": 15.0, "1": 85.0}},
            "having_IP_Address": {"counts": {"-1": 200, "1": 800}, "percentages": {"-1": 20.0, "1": 80.0}},
            "Prefix_Suffix": {"counts": {"-1": 1000, "1": 0}, "percentages": {"-1": 100.0, "1": 0.0}},
            "having_Sub_Domain": {"counts": {"-1": 300, "0": 200, "1": 500}, "percentages": {"-1": 30.0, "0": 20.0, "1": 50.0}},
            "SSLfinal_State": {"counts": {"-1": 600, "0": 200, "1": 200}, "percentages": {"-1": 60.0, "0": 20.0, "1": 20.0}},
            "URL_Length": {"counts": {"-1": 700, "0": 50, "1": 250}, "percentages": {"-1": 70.0, "0": 5.0, "1": 25.0}},
            "port": {"counts": {"-1": 100, "1": 900}, "percentages": {"-1": 10.0, "1": 90.0}},
            "HTTPS_token": {"counts": {"-1": 100, "1": 900}, "percentages": {"-1": 10.0, "1": 90.0}},
        },
        "top_signals": [
            {"feature_name": "Prefix_Suffix", "feature_value": -1, "signal_name": "Prefix_Suffix == -1", "count": 1000, "percentage": 100.0},
            {"feature_name": "URL_Length", "feature_value": -1, "signal_name": "URL_Length == -1", "count": 700, "percentage": 70.0},
            {"feature_name": "SSLfinal_State", "feature_value": -1, "signal_name": "SSLfinal_State == -1", "count": 600, "percentage": 60.0},
        ],
        "clustering": {
            "algorithm": "KMeans",
            "n_clusters": 2,
            "cluster_sizes": [
                {"cluster_id": 0, "member_count": 600, "percentage": 60.0},
                {"cluster_id": 1, "member_count": 400, "percentage": 40.0},
            ]
        },
        "unusual_patterns": {
            "rare_pattern_count": 20,
            "rare_sample_count": 30,
            "rare_sample_percentage": 3.0,
            "rarity_count_threshold": 2,
        },
        "summary": {
            "timestamp_handling_disclosure": {
                "historical_time_trends_available": False,
            }
        }
    }


def test_rule_registry_contains_20_rules():
    assert len(ALL_RULES) == 20


def test_rule_1_trigger_and_not_trigger():
    config = RecommendationConfig(rule_1_min_count=50, rule_1_min_percentage=5.0)
    bundle = _make_synthetic_bundle()
    res = evaluate_rule_1_shortened_url(bundle, config, "10_features")
    assert res["status"] == "triggered"
    assert res["evidence"]["count"] == 150
    assert "expand shortened links" in res["recommendation"]

    # Test not triggered when below threshold
    config_high = RecommendationConfig(rule_1_min_count=500, rule_1_min_percentage=50.0)
    res_high = evaluate_rule_1_shortened_url(bundle, config_high, "10_features")
    assert res_high["status"] == "not_triggered"


def test_rule_2_ip_address_links():
    config = RecommendationConfig()
    bundle = _make_synthetic_bundle()
    res = evaluate_rule_2_ip_address_links(bundle, config, "10_features")
    assert res["status"] == "triggered"
    assert res["evidence"]["count"] == 200
    assert "raw IP addresses" in res["recommendation"]


def test_rule_3_lookalike_domain():
    config = RecommendationConfig()
    bundle = _make_synthetic_bundle()
    res = evaluate_rule_3_lookalike_domain(bundle, config, "10_features")
    assert res["status"] == "triggered"
    assert res["evidence"]["percentage"] == 100.0


def test_rule_19_control_effectiveness_time_series_insufficient_evidence():
    config = RecommendationConfig()
    bundle = _make_synthetic_bundle()
    # When historical_time_trends_available is False, must strictly return insufficient_evidence
    res = evaluate_rule_19_control_effectiveness(bundle, config, "10_features")
    assert res["status"] == "insufficient_evidence"
    assert "Time-series trend evaluation is not supported" in res["trigger_reason"]


def test_rule_missing_evidence_safe_handling():
    config = RecommendationConfig()
    empty_bundle = {"model_type": "10_features"}
    for rule in ALL_RULES:
        res = rule(empty_bundle, config, "10_features")
        assert res["status"] in ("insufficient_evidence", "not_triggered")
        assert res["evidence"] is not None
        assert res["recommendation"] != ""


def test_no_urls_in_rule_outputs():
    config = RecommendationConfig()
    bundle = _make_synthetic_bundle()
    for rule in ALL_RULES:
        res = rule(bundle, config, "10_features")
        res_str = str(res)
        assert "http://" not in res_str
        assert "https://" not in res_str
        assert "evil.com" not in res_str
