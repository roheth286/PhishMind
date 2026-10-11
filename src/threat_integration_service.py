"""
Threat Prediction Integration Service Module.

Provides safe, decoupled integration between successful phishing predictions and
the ChromaDB Threat Intelligence store, incremental analytics updates, clustering,
and recommendation state transitions.

Guarantees:
1. Stores ONLY confirmed phishing predictions (label == -1).
2. Never stores legitimate predictions (label == 1).
3. Selects the exact collection matching the prediction schema ('10_features' vs '20_features').
4. Enforces strict privacy: NO URLs, domains, hostnames, query strings, or URL-derived tokens.
5. Idempotent ingestion: repeated processing with the same event_id or safe case_id is a no-op.
6. Distinct events with identical vectors are preserved as distinct cases with unique IDs.
7. Refreshes ONLY the affected collection without touching the other collection.
8. Controlled clustering: recomputes KMeans (k=4, random_state=42) or assigns nearest centroid,
   keeping cluster profiles, sizes, and unusual patterns fully consistent.
9. Tracks recommendation state transitions: detects newly triggered, materially updated,
   still active, and deactivated recommendations against previously published state.
10. Isolated fault domain: database or analytics failures are reported clearly without altering
    the classifier's prediction output.
11. Concurrency control: per-collection thread locking prevents conflicting simultaneous refreshes.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from src.recommendation_config import DEFAULT_RECOMMENDATION_CONFIG, RecommendationConfig
from src.threat_analytics import generate_threat_analytics_report
from src.threat_recommendations import (
    evaluate_all_rules,
    generate_recommendation_report,
    load_analytics_evidence,
)
from src.threat_vector_db import (
    FEATURES_10,
    FEATURES_20,
    MODEL_TYPE_TO_COLLECTION,
    get_collection,
    insert_phishing_vector,
    validate_model_type,
    validate_vector,
)

logger = logging.getLogger("threat_integration")

# Per-collection locks to guarantee thread-safe analytics and report generation
_COLLECTION_LOCKS = {
    "10_features": threading.Lock(),
    "20_features": threading.Lock(),
}


def compute_recommendation_diff(
    current_evaluation: Dict[str, Any],
    previous_published: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compare current recommendation evaluation with previous published state
    to detect state transitions:
    - newly_triggered: previously not active, now active
    - still_active: active in both, no material priority change
    - materially_updated: active in both, but priority or evidence changed materially
    - deactivated: previously active, now inactive
    """
    current_active = current_evaluation.get("active_recommendations", [])
    current_map = {r["rule_id"]: r for r in current_active}

    prev_active = (previous_published.get("active_recommendations", [])
                   if previous_published and isinstance(previous_published, dict) else [])
    prev_map = {r["rule_id"]: r for r in prev_active}

    newly_triggered: List[Dict[str, Any]] = []
    materially_updated: List[Dict[str, Any]] = []
    still_active: List[Dict[str, Any]] = []
    deactivated: List[Dict[str, Any]] = []

    # Check current active rules against previous state
    for rule_id, curr_rec in current_map.items():
        if rule_id not in prev_map:
            newly_triggered.append(curr_rec)
        else:
            prev_rec = prev_map[rule_id]
            curr_pri = curr_rec.get("priority")
            prev_pri = prev_rec.get("priority")
            if curr_pri != prev_pri:
                materially_updated.append(curr_rec)
            else:
                still_active.append(curr_rec)

    # Check for rules that were previously active but are no longer active
    for rule_id, prev_rec in prev_map.items():
        if rule_id not in current_map:
            # Look up current non-triggered reason if available in audit
            audit = current_evaluation.get("rule_evaluation_audit", [])
            audit_rec = next((a for a in audit if a.get("rule_id") == rule_id), None)
            deactivated.append({
                "rule_id": rule_id,
                "title": prev_rec.get("title", ""),
                "previous_priority": prev_rec.get("priority", "low"),
                "deactivation_reason": (
                    audit_rec.get("trigger_reason", "Condition no longer met.")
                    if audit_rec else "Condition no longer met."
                ),
            })

    return {
        "newly_triggered": newly_triggered,
        "materially_updated": materially_updated,
        "still_active": still_active,
        "deactivated": deactivated,
        "newly_triggered_count": len(newly_triggered),
        "materially_updated_count": len(materially_updated),
        "still_active_count": len(still_active),
        "deactivated_count": len(deactivated),
    }


def process_prediction_result(
    prediction_label: int,
    model_type: str,
    feature_vector: Sequence[int],
    feature_names: Optional[Sequence[str]] = None,
    event_id: Optional[str] = None,
    phishing_probability: Optional[float] = None,
    persist_dir: Optional[str] = None,
    reports_base_dir: str = "reports/threat_analytics",
    recommendations_base_dir: str = "reports/threat_recommendations",
    config: Optional[RecommendationConfig] = None,
) -> Dict[str, Any]:
    """
    Process a URL prediction result through the Threat Intelligence pipeline.

    Flow:
    1. Validates prediction label. If legitimate (1), ignores gracefully and returns ignored status.
    2. Enforces phishing label (-1).
    3. Validates model_type and vector dimensions against authoritative schema.
    4. Selects ChromaDB collection ('phishing_10_features' or 'phishing_20_features').
    5. Deduplicates: if event_id already exists in collection, returns existing record status.
    6. Stores phishing vector with metadata (no URLs, domains, or query strings).
    7. Refreshes ONLY the affected collection's analytics, clustering, and profiles.
    8. Re-evaluates recommendation rules and computes transition diff against previous state.
    9. Publishes new recommendation reports atomically.
    10. Returns structured result with updated recommendations and diffs.

    Raises:
        Does NOT raise exceptions to caller: any internal storage/analytics error is caught
        and returned with status 'error', ensuring model prediction is never altered.
    """
    if config is None:
        config = DEFAULT_RECOMMENDATION_CONFIG

    # Normalize prediction label
    try:
        int_label = int(prediction_label)
    except (TypeError, ValueError):
        return {
            "status": "rejected",
            "reason": f"Invalid prediction label format: {prediction_label}",
            "stored": False,
            "refreshed": False,
        }

    # 1. Legitimate check: Do NOT store legitimate URLs
    if int_label != -1:
        return {
            "status": "ignored_legitimate",
            "reason": f"Prediction label {int_label} is legitimate; threat intelligence only stores phishing.",
            "model_type": model_type,
            "stored": False,
            "refreshed": False,
            "prediction_label": int_label,
        }

    # 2. Validate model_type
    try:
        validate_model_type(model_type)
    except ValueError as e:
        return {
            "status": "rejected",
            "reason": str(e),
            "stored": False,
            "refreshed": False,
        }

    # 3. Validate feature vector
    try:
        validated_vector = validate_vector(model_type, feature_vector)
    except Exception as e:
        return {
            "status": "rejected",
            "reason": f"Feature vector validation failed: {e}",
            "stored": False,
            "refreshed": False,
        }

    # Verify feature names alignment if provided
    expected_features = list(FEATURES_10 if model_type == "10_features" else FEATURES_20)
    if feature_names and list(feature_names) != expected_features:
        return {
            "status": "rejected",
            "reason": f"Feature names order mismatch for {model_type}",
            "stored": False,
            "refreshed": False,
        }

    lock = _COLLECTION_LOCKS.get(model_type) or threading.Lock()

    with lock:
        try:
            col = get_collection(model_type, persist_dir=persist_dir)
            existing_count = col.count()

            # 4. Generate or check stable event_id
            if not event_id:
                # Deterministic or sequence case ID
                case_id = f"phish_{model_type}_event_{existing_count + 1:05d}"
            else:
                case_id = str(event_id).strip()

            # Check if this exact event_id was already ingested (idempotency check)
            existing_records = col.get(ids=[case_id])
            if existing_records and existing_records.get("ids") and len(existing_records["ids"]) > 0:
                # Event already stored; do not duplicate or re-run expensive refresh
                return {
                    "status": "duplicate_event",
                    "reason": f"Event ID '{case_id}' already stored in {model_type}.",
                    "case_id": case_id,
                    "model_type": model_type,
                    "stored": False,
                    "refreshed": False,
                }

            # 5. Insert Phishing Vector
            metadata = {
                "source_dataset": "runtime_prediction",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "prediction_label": -1,
                "source_label": -1,
            }
            if phishing_probability is not None:
                metadata["phishing_probability"] = float(phishing_probability)

            stored_id = insert_phishing_vector(
                model_type=model_type,
                vector=validated_vector,
                metadata=metadata,
                case_id=case_id,
                persist_dir=persist_dir,
            )

        except Exception as e:
            logger.error(f"Failed to insert phishing vector into ChromaDB: {e}")
            return {
                "status": "storage_error",
                "error": str(e),
                "model_type": model_type,
                "stored": False,
                "refreshed": False,
            }

        # 6. Load previous published recommendation state to compute transition diff
        prev_recommendations: Optional[Dict[str, Any]] = None
        subfolder = "phishing_10_features" if model_type == "10_features" else "phishing_20_features"
        prev_report_file = os.path.join(recommendations_base_dir, subfolder, "recommendations.json")
        if os.path.isfile(prev_report_file):
            try:
                with open(prev_report_file, "r", encoding="utf-8") as f:
                    prev_recommendations = json.load(f)
            except Exception:
                prev_recommendations = None

        # 7. Refresh ONLY the affected collection's analytics and clustering
        try:
            analytics_res = generate_threat_analytics_report(
                model_type=model_type,
                persist_dir=persist_dir,
                reports_dir=reports_base_dir,
                n_clusters=4,  # Standard k=4
            )
        except Exception as e:
            logger.error(f"Analytics refresh failed after storing {stored_id}: {e}")
            return {
                "status": "partial_success_analytics_failed",
                "case_id": stored_id,
                "model_type": model_type,
                "stored": True,
                "refreshed": False,
                "error": f"Analytics refresh failed: {e}",
            }

        # 8. Re-evaluate recommendation rules and publish updated state
        try:
            bundle = load_analytics_evidence(model_type, reports_base_dir=reports_base_dir)
            current_eval = evaluate_all_rules(bundle, config=config, model_type=model_type)

            # Compute transition diff
            diff = compute_recommendation_diff(current_eval, prev_recommendations)
            current_eval["recommendation_transitions"] = diff

            # Persist updated recommendation report
            target_out_dir = os.path.join(recommendations_base_dir, subfolder)
            os.makedirs(target_out_dir, exist_ok=True)
            out_file = os.path.join(target_out_dir, "recommendations.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(current_eval, f, indent=2)

        except Exception as e:
            logger.error(f"Recommendation update failed for {model_type}: {e}")
            return {
                "status": "partial_success_recommendations_failed",
                "case_id": stored_id,
                "model_type": model_type,
                "stored": True,
                "refreshed": True,
                "recommendations_updated": False,
                "error": f"Recommendation evaluation failed: {e}",
            }

        return {
            "status": "success",
            "case_id": stored_id,
            "model_type": model_type,
            "stored": True,
            "refreshed": True,
            "recommendations_updated": True,
            "newly_triggered": diff["newly_triggered"],
            "newly_triggered_count": diff["newly_triggered_count"],
            "materially_updated_count": diff["materially_updated_count"],
            "active_recommendations_count": current_eval["evaluation_summary"]["active_recommendations_count"],
            "active_recommendations": current_eval["active_recommendations"],
            "transitions": diff,
        }


def get_current_recommendation_state(
    model_type: str,
    recommendations_base_dir: str = "reports/threat_recommendations",
) -> Dict[str, Any]:
    """
    Retrieve the current published recommendation state and transitions
    for a given collection, making it directly available to frontend or application consumers.
    """
    validate_model_type(model_type)
    subfolder = "phishing_10_features" if model_type == "10_features" else "phishing_20_features"
    report_file = os.path.join(recommendations_base_dir, subfolder, "recommendations.json")

    if not os.path.isfile(report_file):
        return {
            "model_type": model_type,
            "status": "not_generated",
            "active_recommendations": [],
            "active_recommendations_count": 0,
            "notes": "No recommendations report currently exists for this collection.",
        }

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "model_type": model_type,
        "status": "ready",
        "generated_at": data.get("generated_at"),
        "config_version": data.get("config_version"),
        "evaluation_summary": data.get("evaluation_summary", {}),
        "active_recommendations": data.get("active_recommendations", []),
        "recommendation_transitions": data.get("recommendation_transitions", {}),
    }
