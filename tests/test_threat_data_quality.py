"""
Tests for threat intelligence data quality audit module.
"""

import math
import pytest
from src.threat_data_quality import audit_collection_data_quality, validate_single_record


def test_validate_single_record_valid_10_features():
    record_id = "test_rec_1"
    # FEATURES_10: having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol,
    #              double_slash_redirecting, Prefix_Suffix, having_Sub_Domain, HTTPS_token,
    #              SSLfinal_State, port
    # port allows {1, -1}; HTTPS_token allows {1, -1}; SSLfinal_State allows {1, 0, -1}
    vector = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    metadata = {
        "record_id": record_id,
        "model_type": "10_features",
        "source_label": -1,
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
        "feature_names": '["having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "HTTPS_token", "SSLfinal_State", "port"]',
        "feature_values": "[-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert issues == []


def test_validate_single_record_dimension_mismatch():
    record_id = "test_rec_2"
    vector = [-1, 1, 1]  # expected 10
    metadata = {
        "model_type": "10_features",
        "source_label": -1,
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert any("dimension_mismatch" in iss for iss in issues)


def test_validate_single_record_illegal_categorical_value():
    record_id = "test_rec_3"
    # having_IP_Address only allows {-1, 1}; 0 is illegal for it
    vector = [0, 1, 1, 1, -1, 1, -1, 1, 1, 0]
    metadata = {
        "model_type": "10_features",
        "source_label": -1,
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert any("unallowed_categorical_value_having_IP_Address" in iss for iss in issues)


def test_validate_single_record_nan_and_inf_values():
    record_id = "test_rec_4"
    vector = [float("nan"), 1, 1, 1, -1, 1, -1, 1, 1, 0]
    metadata = {
        "model_type": "10_features",
        "source_label": -1,
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert any("non_finite_or_nan" in iss for iss in issues)


def test_validate_single_record_prohibited_url_metadata():
    record_id = "test_rec_5"
    vector = [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]
    metadata = {
        "model_type": "10_features",
        "source_label": -1,
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
        "url": "http://evil-phishing.com/login",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert any("prohibited_url_metadata_key" in iss for iss in issues)


def test_validate_single_record_non_phishing_label():
    record_id = "test_rec_6"
    vector = [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]
    metadata = {
        "model_type": "10_features",
        "source_label": 1,  # Legitimate! Should fail phishing-only audit
        "prediction_label": -1,
        "observed_at": "2026-10-10T12:00:00+00:00",
    }
    issues = validate_single_record(record_id, vector, metadata, "10_features")
    assert any("non_phishing_source_label" in iss for iss in issues)


def test_audit_collection_data_quality_both_collections():
    # Audits real stored ChromaDB collections
    for m_type in ["10_features", "20_features"]:
        report, valid_records = audit_collection_data_quality(m_type)
        assert report["status"] == "complete"
        assert report["total_records_examined"] == 4898
        assert report["valid_records_count"] == 4898
        assert report["invalid_records_count"] == 0
        assert report["data_quality_percentage"] == 100.0
        assert len(valid_records) == 4898
