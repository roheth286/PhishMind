"""
Comprehensive unit and integration tests for Phase 4:
Threat Prediction Integration Service, ChromaDB storage, incremental refresh,
clustering preservation, recommendation updates, and pipeline router wiring.
"""

import os
import json
import shutil
import pytest
from unittest.mock import MagicMock, patch

from src.pipeline_router import route_url, RoutingResult
from src.threat_integration_service import (
    compute_recommendation_diff,
    get_current_recommendation_state,
    process_prediction_result,
)
from src.threat_vector_db import get_collection, initialize_collections


@pytest.fixture
def temp_env(tmp_path):
    """Setup isolated ChromaDB and report paths with copied baseline reports."""
    temp_chroma = str(tmp_path / "chroma_db")
    temp_analytics = str(tmp_path / "reports" / "threat_analytics")
    temp_recs = str(tmp_path / "reports" / "threat_recommendations")

    # Copy real baseline reports from project into temp_env
    for m in ["phishing_10_features", "phishing_20_features"]:
        src_an = os.path.join("reports", "threat_analytics", m)
        dst_an = os.path.join(temp_analytics, m)
        if os.path.isdir(src_an):
            shutil.copytree(src_an, dst_an)

        src_rc = os.path.join("reports", "threat_recommendations", m)
        dst_rc = os.path.join(temp_recs, m)
        if os.path.isdir(src_rc):
            shutil.copytree(src_rc, dst_rc)

    # Initialize empty collections in temp chroma
    initialize_collections(persist_dir=temp_chroma)

    return {
        "chroma_dir": temp_chroma,
        "analytics_dir": temp_analytics,
        "recs_dir": temp_recs,
    }


def test_legitimate_predictions_not_stored(temp_env):
    """Legitimate predictions (label 1) must never be stored in ChromaDB or trigger refresh."""
    vec = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    res = process_prediction_result(
        prediction_label=1,
        model_type="10_features",
        feature_vector=vec,
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )

    assert res["status"] == "ignored_legitimate"
    assert res["stored"] is False
    assert res["refreshed"] is False

    col = get_collection("10_features", persist_dir=temp_env["chroma_dir"])
    assert col.count() == 0


def test_invalid_label_or_schema_rejected(temp_env):
    """Invalid labels or dimension mismatches must be rejected safely."""
    # Invalid label
    res_label = process_prediction_result(
        prediction_label="invalid",
        model_type="10_features",
        feature_vector=[-1] * 10,
        persist_dir=temp_env["chroma_dir"],
    )
    assert res_label["status"] == "rejected"
    assert res_label["stored"] is False

    # Dimension mismatch: 5 items for 10-feature model
    res_dim = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=[-1, 1, 1, 1, 1],
        persist_dir=temp_env["chroma_dir"],
    )
    assert res_dim["status"] == "rejected"
    assert "dimension mismatch" in res_dim["reason"]


def test_phishing_10_features_stored_only_in_10_features_collection(temp_env):
    """A 10-feature phishing prediction must insert ONLY into phishing_10_features."""
    vec = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    res = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=vec,
        event_id="evt_test_10_001",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )

    assert res["status"] == "success"
    assert res["stored"] is True
    assert res["refreshed"] is True
    assert res["model_type"] == "10_features"

    col_10 = get_collection("10_features", persist_dir=temp_env["chroma_dir"])
    col_20 = get_collection("20_features", persist_dir=temp_env["chroma_dir"])

    assert col_10.count() == 1
    assert col_20.count() == 0  # Unaffected collection untouched

    # Verify no URLs or domains stored in metadata
    record = col_10.get(ids=["evt_test_10_001"])
    meta = record["metadatas"][0]
    for k, v in meta.items():
        assert "url" not in str(k).lower()
        # Verify no actual URL scheme or domain targets were stored
        assert "http://" not in str(v).lower()
        assert "https://" not in str(v).lower()
        assert ".com" not in str(v).lower()


def test_phishing_20_features_stored_only_in_20_features_collection(temp_env):
    """A 20-feature phishing prediction must insert ONLY into phishing_20_features."""
    vec = [-1, 1, 1, 1, -1, 1, -1, 0, 1, 1, 1, -1, -1, 0, -1, 1, 1, 0, 1, 1]
    res = process_prediction_result(
        prediction_label=-1,
        model_type="20_features",
        feature_vector=vec,
        event_id="evt_test_20_001",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )

    assert res["status"] == "success"
    assert res["stored"] is True
    assert res["refreshed"] is True
    assert res["model_type"] == "20_features"

    col_10 = get_collection("10_features", persist_dir=temp_env["chroma_dir"])
    col_20 = get_collection("20_features", persist_dir=temp_env["chroma_dir"])

    assert col_20.count() == 1
    assert col_10.count() == 0  # 10-feature collection untouched


def test_idempotent_duplicate_event_handling(temp_env):
    """Reprocessing the same event_id must be an idempotent no-op."""
    vec = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    # First ingestion
    res1 = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=vec,
        event_id="evt_duplicate_test",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )
    assert res1["status"] == "success"
    assert res1["stored"] is True

    # Duplicate retry
    res2 = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=vec,
        event_id="evt_duplicate_test",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )
    assert res2["status"] == "duplicate_event"
    assert res2["stored"] is False
    assert res2["refreshed"] is False

    col = get_collection("10_features", persist_dir=temp_env["chroma_dir"])
    assert col.count() == 1


def test_distinct_events_with_identical_vectors_preserved(temp_env):
    """Two separate prediction events with identical vectors must both be stored under unique IDs."""
    vec = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]

    res1 = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=vec,
        event_id="evt_incident_A",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )
    res2 = process_prediction_result(
        prediction_label=-1,
        model_type="10_features",
        feature_vector=vec,
        event_id="evt_incident_B",
        persist_dir=temp_env["chroma_dir"],
        reports_base_dir=temp_env["analytics_dir"],
        recommendations_base_dir=temp_env["recs_dir"],
    )

    assert res1["stored"] is True
    assert res2["stored"] is True

    col = get_collection("10_features", persist_dir=temp_env["chroma_dir"])
    assert col.count() == 2


def test_recommendation_transitions_diff(temp_env):
    """Verify compute_recommendation_diff accurately tracks transitions."""
    prev_state = {
        "active_recommendations": [
            {"rule_id": "RULE_01_SHORTENED_URL", "title": "Shortened URL", "priority": "medium"},
            {"rule_id": "RULE_02_IP_ADDRESS_LINKS", "title": "IP links", "priority": "high"},
            {"rule_id": "RULE_03_OLD_RULE", "title": "Old", "priority": "low"},
        ]
    }
    curr_eval = {
        "active_recommendations": [
            {"rule_id": "RULE_01_SHORTENED_URL", "title": "Shortened URL", "priority": "high"},  # materially updated
            {"rule_id": "RULE_02_IP_ADDRESS_LINKS", "title": "IP links", "priority": "high"},   # still active
            {"rule_id": "RULE_04_NEW_RULE", "title": "New rule", "priority": "medium"},           # newly triggered
        ],
        "rule_evaluation_audit": [
            {"rule_id": "RULE_03_OLD_RULE", "trigger_reason": "No longer meets threshold."}
        ]
    }

    diff = compute_recommendation_diff(curr_eval, prev_state)
    assert diff["newly_triggered_count"] == 1
    assert diff["newly_triggered"][0]["rule_id"] == "RULE_04_NEW_RULE"

    assert diff["materially_updated_count"] == 1
    assert diff["materially_updated"][0]["rule_id"] == "RULE_01_SHORTENED_URL"

    assert diff["still_active_count"] == 1
    assert diff["still_active"][0]["rule_id"] == "RULE_02_IP_ADDRESS_LINKS"

    assert diff["deactivated_count"] == 1
    assert diff["deactivated"][0]["rule_id"] == "RULE_03_OLD_RULE"


def test_get_current_recommendation_state(temp_env):
    """Application query interface returns current active recommendations."""
    state = get_current_recommendation_state(
        model_type="10_features",
        recommendations_base_dir=temp_env["recs_dir"],
    )
    assert state["status"] == "ready"
    assert state["model_type"] == "10_features"
    assert len(state["active_recommendations"]) > 0


@patch("src.pipeline_router.check_url_resource")
@patch("src.pipeline_router.predict_url_10")
def test_pipeline_router_wiring_phishing_triggers_threat_intel(mock_predict_10, mock_check, temp_env):
    """When route_url predicts phishing with update_threat_intel=True, threat intel is populated."""
    mock_check.return_value = (False, "Non-HTML status", 404, "text/plain", "http://test-phish.com")
    vec = [-1, 1, 1, 1, -1, 1, -1, 1, 0, 1]
    mock_predict_10.return_value = (-1, 0.95, vec)

    # Patch process_prediction_result to verify exact arguments
    with patch("src.pipeline_router.process_prediction_result") as mock_process:
        mock_process.return_value = {"status": "success", "stored": True, "refreshed": True}

        res = route_url(
            "http://test-phish.com",
            update_threat_intel=True,
            event_id="evt_router_phish_001",
        )

        assert res.predicted_label == -1
        assert res.pipeline == "10-feature"
        assert res.threat_intel is not None
        assert res.threat_intel["status"] == "success"

        mock_process.assert_called_once_with(
            prediction_label=-1,
            model_type="10_features",
            feature_vector=vec,
            phishing_probability=0.95,
            event_id="evt_router_phish_001",
        )
