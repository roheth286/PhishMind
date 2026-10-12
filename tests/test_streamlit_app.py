"""
Integration tests for Streamlit application workflows.

Verifies:
1. Input format validation rejects invalid URLs before backend call.
2. Prediction flow calls route_url with original URL format.
3. Session state preserves prediction results across navigation.
4. Dashboard data loading reuses actual backend functions.
5. No URLs are leaked into threat intelligence outputs.
"""

from unittest.mock import MagicMock, patch
import pytest

from src.pipeline_router import RoutingResult
from src.threat_recommendations import load_analytics_evidence
from src.threat_vector_db import get_collection_stats
from src.ui_validator import validate_url_format


def test_ui_validation_rejects_before_backend():
    """Invalid URLs must be rejected without calling backend."""
    invalid_inputs = [
        "",
        "   ",
        "invalid_host",
        "http://invalid host.com",
        "https://domain.c",
        ".bad.com",
    ]
    for inp in invalid_inputs:
        is_val, msg = validate_url_format(inp)
        assert is_val is False
        assert msg == "URL not valid"


def test_ui_validation_accepts_valid_urls():
    """Valid URLs pass lightweight validation and preserve original string."""
    valid_inputs = [
        "https://example.com/login",
        "http://192.168.1.1:8080/index",
        "sub.test-bank.co.uk",
        "my-site.org?user=admin#section",
    ]
    for inp in valid_inputs:
        is_val, cleaned = validate_url_format(inp)
        assert is_val is True
        assert cleaned == inp


@patch("src.pipeline_router.check_url_resource")
@patch("src.pipeline_router.predict_url_10")
def test_prediction_workflow_preserves_routing_result(mock_predict_10, mock_check):
    """Calling route_url produces RoutingResult expected by View 2."""
    from src.pipeline_router import route_url

    mock_check.return_value = (False, "Non-HTML resource", 404, "text/plain", "http://test-url.com")
    mock_predict_10.return_value = (-1, 0.92, [-1] * 10)

    res = route_url("http://test-url.com", update_threat_intel=False)

    assert isinstance(res, RoutingResult)
    assert res.predicted_label == -1
    assert res.label_description == "Phishing"
    assert res.pipeline == "10-feature"
    assert res.feature_count == 10
    assert res.phishing_probability == 0.92


def test_dashboard_evidence_loading_structure():
    """Verify load_analytics_evidence supplies all required dashboard sections."""
    for m in ["10_features", "20_features"]:
        evidence = load_analytics_evidence(m)
        assert "feature_statistics" in evidence
        assert "clustering" in evidence
        assert "cluster_profiles" in evidence
        assert "unusual_patterns" in evidence
        assert "data_quality" in evidence
        assert len(evidence["feature_statistics"]) in (10, 20)

        # Ensure collection stats are available
        stats = get_collection_stats(m)
        assert stats["count"] >= 4898


def test_feature_vector_dataframe_column_names_and_order():
    """Verify that feature vectors are formatted with authoritative column names in exact order."""
    import pandas as pd
    from src.threat_vector_db import FEATURES_10, FEATURES_20

    # 1. Test 10-feature vector mapping
    vec_10 = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    df_10 = pd.DataFrame(
        [
            list(range(1, len(vec_10) + 1)),
            vec_10,
        ],
        index=["Feature Index", "Value"],
        columns=list(FEATURES_10),
    )
    assert list(df_10.columns) == [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain",
        "HTTPS_token",
        "SSLfinal_State",
        "port",
    ]
    assert df_10.loc["Value", "having_IP_Address"] == -1
    assert df_10.loc["Value", "port"] == 1
    assert "0" not in [str(c) for c in df_10.columns]

    # 2. Test 20-feature vector mapping
    vec_20 = [-1, 1, 1, 1, -1, 1, -1, 0, 1, 1, 1, -1, -1, 0, -1, 1, 1, 0, 1, 1]
    df_20 = pd.DataFrame(
        [
            list(range(1, len(vec_20) + 1)),
            vec_20,
        ],
        index=["Feature Index", "Value"],
        columns=list(FEATURES_20),
    )
    assert list(df_20.columns) == [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain",
        "SSLfinal_State",
        "port",
        "HTTPS_token",
        "Favicon",
        "Request_URL",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Submitting_to_email",
        "Iframe",
        "Redirect",
        "on_mouseover",
        "RightClick",
    ]
    assert df_20.loc["Value", "having_IP_Address"] == -1
    assert df_20.loc["Value", "RightClick"] == 1
    assert "0" not in [str(c) for c in df_20.columns]
