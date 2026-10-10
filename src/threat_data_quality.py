"""
Threat Intelligence Data Quality Module.

Performs read-only validation, auditing, and anomaly detection on records stored
in the ChromaDB Threat Intelligence vector collections ('phishing_10_features'
and 'phishing_20_features').

Validates:
- Exact vector dimensionality and allowed categorical values (-1, 0, 1).
- Non-numeric, infinite, or missing values.
- Schema matching for feature names and ordering.
- Strict phishing-only enforcement (source_label == -1, prediction_label == -1).
- Metadata integrity, uniqueness, and timestamp validity.
- Detection of duplicate feature vectors.
"""

import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from src.threat_vector_db import (
    ALLOWED_VALUES_10,
    ALLOWED_VALUES_20,
    FEATURES_10,
    FEATURES_20,
    MODEL_TYPE_TO_COLLECTION,
    get_collection,
    validate_model_type,
)


def validate_single_record(
    record_id: str,
    vector: Optional[List[float]],
    metadata: Optional[Dict[str, Any]],
    model_type: str
) -> List[str]:
    """
    Validate a single ChromaDB record against the authoritative schema for model_type.
    Returns a list of issue descriptions (empty if record is fully valid).
    """
    issues: List[str] = []
    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    allowed_values = ALLOWED_VALUES_10 if model_type == "10_features" else ALLOWED_VALUES_20

    # 1. Check Record ID
    if not record_id or not str(record_id).strip():
        issues.append("missing_record_id")

    # 2. Check Vector Existence and Dimension
    if vector is None:
        issues.append("missing_vector")
        return issues

    if len(vector) != len(expected_features):
        issues.append(
            f"dimension_mismatch: expected {len(expected_features)} features, got {len(vector)}"
        )

    # 3. Check Vector Feature Values
    for idx, (feat_name, val) in enumerate(zip(expected_features, vector)):
        if val is None or math.isnan(val) or math.isinf(val):
            issues.append(f"invalid_value_{feat_name}: non_finite_or_nan")
            continue

        try:
            int_val = int(round(val))
            if abs(val - int_val) > 1e-5:
                issues.append(f"non_integer_value_{feat_name}: {val}")
                continue
        except (ValueError, TypeError, OverflowError):
            issues.append(f"non_numeric_value_{feat_name}: {val}")
            continue

        allowed = allowed_values.get(feat_name, {-1, 1})
        if int_val not in allowed:
            issues.append(
                f"unallowed_categorical_value_{feat_name}: {int_val} not in {sorted(list(allowed))}"
            )

    # 4. Check Metadata Integrity
    if metadata is None or not isinstance(metadata, dict):
        issues.append("missing_or_invalid_metadata_dict")
        return issues

    # 4.1 Prohibited URL / Domain fields
    for k in metadata.keys():
        k_lower = str(k).lower()
        if any(term in k_lower for term in ("url", "domain", "hostname", "path", "href")):
            issues.append(f"prohibited_url_metadata_key: {k}")

    # 4.2 Model Type Alignment
    rec_model_type = metadata.get("model_type")
    if rec_model_type != model_type:
        issues.append(f"metadata_model_type_mismatch: expected '{model_type}', got '{rec_model_type}'")

    # 4.3 Phishing-only Label Validation
    src_label = metadata.get("source_label")
    pred_label = metadata.get("prediction_label")

    if src_label is None:
        issues.append("missing_source_label")
    elif int(src_label) != -1:
        issues.append(f"non_phishing_source_label: {src_label} (must be -1)")

    if pred_label is None:
        issues.append("missing_prediction_label")
    elif int(pred_label) != -1:
        issues.append(f"non_phishing_prediction_label: {pred_label} (must be -1)")

    # 4.4 Feature names and values metadata consistency
    if "feature_names" in metadata:
        try:
            stored_fnames = json.loads(metadata["feature_names"])
            if stored_fnames != list(expected_features):
                issues.append("feature_names_metadata_order_mismatch")
        except Exception:
            issues.append("malformed_feature_names_json")

    if "feature_values" in metadata and len(vector) == len(expected_features):
        try:
            stored_fvals = json.loads(metadata["feature_values"])
            vector_ints = [int(round(x)) for x in vector]
            if stored_fvals != vector_ints:
                issues.append("feature_values_metadata_vector_mismatch")
        except Exception:
            issues.append("malformed_feature_values_json")

    # 4.5 Timestamp format
    observed_at = metadata.get("observed_at")
    if not observed_at:
        issues.append("missing_observed_at_timestamp")
    else:
        try:
            datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
        except Exception:
            issues.append(f"malformed_iso_timestamp: {observed_at}")

    return issues


def audit_collection_data_quality(
    model_type: str,
    persist_dir: Optional[str] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Perform a complete, read-only data quality audit on a ChromaDB collection.

    Returns:
        (report_dict, valid_records_list)
        where:
        - report_dict contains summary stats, issues, and metadata.
        - valid_records_list contains records that passed all checks for downstream analytics.
    """
    validate_model_type(model_type)
    col = get_collection(model_type, persist_dir=persist_dir)
    total_count = col.count()

    if total_count == 0:
        empty_report: Dict[str, Any] = {
            "model_type": model_type,
            "collection_name": MODEL_TYPE_TO_COLLECTION[model_type],
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "empty_collection",
            "total_records_examined": 0,
            "valid_records_count": 0,
            "invalid_records_count": 0,
            "distinct_vectors_count": 0,
            "duplicate_vectors_count": 0,
            "issues_by_category": {},
            "invalid_record_details": {},
            "data_quality_score": 100.0,
            "notes": "Collection contains no records.",
        }
        return empty_report, []

    # Fetch all records including embeddings and metadata
    raw_data = col.get(include=["embeddings", "metadatas"])
    ids = raw_data.get("ids", [])
    embeddings = raw_data.get("embeddings", [])
    metadatas = raw_data.get("metadatas", [])

    valid_records: List[Dict[str, Any]] = []
    issues_by_category: Dict[str, int] = {}
    invalid_record_details: Dict[str, List[str]] = {}

    distinct_vector_tuples: Set[Tuple[int, ...]] = set()
    total_valid_vector_count = 0

    for idx in range(len(ids)):
        rec_id = ids[idx]
        vec = embeddings[idx] if idx < len(embeddings) else None
        meta = metadatas[idx] if idx < len(metadatas) else None

        rec_issues = validate_single_record(rec_id, vec, meta, model_type)

        if rec_issues:
            invalid_record_details[rec_id] = rec_issues
            for issue in rec_issues:
                cat = issue.split(":")[0]
                issues_by_category[cat] = issues_by_category.get(cat, 0) + 1
        else:
            int_vec = [int(round(x)) for x in vec]
            valid_records.append({
                "id": rec_id,
                "vector": int_vec,
                "metadata": meta,
            })
            distinct_vector_tuples.add(tuple(int_vec))
            total_valid_vector_count += 1

    distinct_count = len(distinct_vector_tuples)
    duplicate_count = total_valid_vector_count - distinct_count

    valid_count = len(valid_records)
    invalid_count = len(invalid_record_details)
    quality_pct = (valid_count / total_count * 100.0) if total_count > 0 else 0.0

    report: Dict[str, Any] = {
        "model_type": model_type,
        "collection_name": MODEL_TYPE_TO_COLLECTION[model_type],
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "complete" if invalid_count == 0 else "partial_failures",
        "total_records_examined": total_count,
        "valid_records_count": valid_count,
        "invalid_records_count": invalid_count,
        "data_quality_percentage": round(quality_pct, 4),
        "distinct_vectors_count": distinct_count,
        "duplicate_vectors_count": duplicate_count,
        "issues_by_category": issues_by_category,
        "invalid_record_details": invalid_record_details,
        "notes": (
            "All records meet authoritative schema requirements."
            if invalid_count == 0
            else f"Detected {invalid_count} records with schema or data quality issues."
        ),
    }

    return report, valid_records
