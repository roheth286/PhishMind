"""
Threat Vector Database Module.

Provides standalone access to ChromaDB persistent vector database storing
historical phishing feature vectors for Threat Intelligence.

Collections:
- 'phishing_10_features': Stores 10-feature historical phishing vectors.
- 'phishing_20_features': Stores 20-feature historical phishing vectors.

This module is independent of the URL prediction pipeline.
Only phishing records (label = -1) are stored in these collections.
No URLs, domains, hostnames, or sensitive data are stored.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import chromadb
from chromadb.api.models.Collection import Collection
import numpy as np

# Authoritative feature schemas
FEATURES_10: Tuple[str, ...] = (
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
)

FEATURES_20: Tuple[str, ...] = (
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
)

ALLOWED_VALUES_20: Dict[str, Set[int]] = {
    "having_IP_Address": {1, -1},
    "URL_Length": {1, 0, -1},
    "Shortining_Service": {1, -1},
    "having_At_Symbol": {1, -1},
    "double_slash_redirecting": {1, -1},
    "Prefix_Suffix": {1, -1},
    "having_Sub_Domain": {1, 0, -1},
    "SSLfinal_State": {1, 0, -1},
    "port": {1, -1},
    "HTTPS_token": {1, -1},
    "Favicon": {1, -1},
    "Request_URL": {1, 0, -1},
    "URL_of_Anchor": {1, 0, -1},
    "Links_in_tags": {1, 0, -1},
    "SFH": {1, 0, -1},
    "Submitting_to_email": {1, -1},
    "Iframe": {1, -1},
    "Redirect": {1, 0, -1},
    "on_mouseover": {1, -1},
    "RightClick": {1, -1},
}

ALLOWED_VALUES_10: Dict[str, Set[int]] = {
    feat: ALLOWED_VALUES_20[feat] for feat in FEATURES_10
}

COLLECTION_10_NAME = "phishing_10_features"
COLLECTION_20_NAME = "phishing_20_features"

VALID_MODEL_TYPES = ("10_features", "20_features")

MODEL_TYPE_TO_COLLECTION = {
    "10_features": COLLECTION_10_NAME,
    "20_features": COLLECTION_20_NAME,
}

MODEL_TYPE_TO_FEATURES = {
    "10_features": FEATURES_10,
    "20_features": FEATURES_20,
}

MODEL_TYPE_TO_ALLOWED = {
    "10_features": ALLOWED_VALUES_10,
    "20_features": ALLOWED_VALUES_20,
}

DEFAULT_PERSIST_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "chroma_db")
)


def resolve_persist_dir(persist_dir: Optional[str] = None) -> str:
    """Resolve the ChromaDB persistent directory path."""
    if persist_dir:
        return os.path.abspath(persist_dir)
    return DEFAULT_PERSIST_DIR


def get_chroma_client(persist_dir: Optional[str] = None) -> chromadb.PersistentClient:
    """Get a persistent ChromaDB client for the given or default path."""
    target_dir = resolve_persist_dir(persist_dir)
    os.makedirs(target_dir, exist_ok=True)
    return chromadb.PersistentClient(path=target_dir)


def validate_model_type(model_type: str) -> None:
    """Validate that model_type is supported."""
    if not isinstance(model_type, str) or model_type not in VALID_MODEL_TYPES:
        raise ValueError(
            f"Invalid model_type: '{model_type}'. Expected one of {VALID_MODEL_TYPES}."
        )


def validate_vector(model_type: str, vector: Sequence[int]) -> List[int]:
    """
    Validate that the feature vector matches the schema for the model_type.
    Returns the vector as a list of integers.
    """
    validate_model_type(model_type)
    expected_features = MODEL_TYPE_TO_FEATURES[model_type]
    allowed_values = MODEL_TYPE_TO_ALLOWED[model_type]

    if not isinstance(vector, (list, tuple)):
        raise TypeError(f"Vector must be a list or tuple of integers, got {type(vector).__name__}.")

    if len(vector) != len(expected_features):
        raise ValueError(
            f"Vector dimension mismatch for '{model_type}': expected {len(expected_features)} values, "
            f"got {len(vector)}."
        )

    int_vector: List[int] = []
    for idx, (feat_name, val) in enumerate(zip(expected_features, vector)):
        # Check numeric conversion, accepting python int/float and numpy scalars
        if isinstance(val, bool) or not isinstance(val, (int, float, np.integer, np.floating)):
            raise TypeError(
                f"Feature '{feat_name}' at index {idx} must be numeric, got {type(val).__name__} ({val})."
            )
        try:
            int_val = int(val)
            if float(val) != float(int_val):
                raise ValueError(
                    f"Feature '{feat_name}' at index {idx} must be an integer, got non-integer float {val}."
                )
        except (ValueError, TypeError, OverflowError) as e:
            raise ValueError(f"Feature '{feat_name}' at index {idx} cannot be parsed as integer: {e}") from e

        allowed = allowed_values[feat_name]
        if int_val not in allowed:
            raise ValueError(
                f"Feature '{feat_name}' value {int_val} is invalid. Allowed values: {sorted(list(allowed))}."
            )
        int_vector.append(int_val)

    return int_vector


def initialize_collections(
    persist_dir: Optional[str] = None
) -> Dict[str, Collection]:
    """
    Initialize or retrieve both ChromaDB collections.
    Returns a dict mapping model_type to its Collection.
    """
    client = get_chroma_client(persist_dir)
    collections: Dict[str, Collection] = {}

    for model_type, col_name in MODEL_TYPE_TO_COLLECTION.items():
        # get_or_create_collection ensures idempotence
        col = client.get_or_create_collection(
            name=col_name,
            metadata={"description": f"Historical phishing threat intelligence vectors for {model_type}"}
        )
        collections[model_type] = col

    return collections


def get_collection(
    model_type: str,
    persist_dir: Optional[str] = None
) -> Collection:
    """
    Retrieve the ChromaDB collection for the specified model_type.
    """
    validate_model_type(model_type)
    client = get_chroma_client(persist_dir)
    col_name = MODEL_TYPE_TO_COLLECTION[model_type]
    return client.get_or_create_collection(name=col_name)


def insert_phishing_vector(
    model_type: str,
    vector: Sequence[int],
    metadata: Optional[Dict[str, Any]] = None,
    case_id: Optional[str] = None,
    persist_dir: Optional[str] = None
) -> str:
    """
    Insert a verified phishing vector into the appropriate ChromaDB collection.

    Requirements enforced:
    - model_type must be '10_features' or '20_features'.
    - Vector must match exact length and allowed categorical values.
    - Result/label must be strictly -1 (Phishing).
    - No URLs or domain strings may be included in metadata.
    """
    validate_model_type(model_type)
    validated_vector = validate_vector(model_type, vector)

    col = get_collection(model_type, persist_dir=persist_dir)
    features = list(MODEL_TYPE_TO_FEATURES[model_type])

    # Check incoming metadata for prohibited data (URLs) or invalid labels
    meta_copy: Dict[str, Any] = {}
    if metadata:
        for k, v in metadata.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in ("url", "domain", "hostname", "path", "href", "http")):
                raise ValueError(f"Prohibited metadata field '{k}' detected: URLs and domains must not be stored.")
            if k in ("source_label", "prediction_label", "Result", "label"):
                if int(v) != -1:
                    raise ValueError(f"Only phishing records (label = -1) are allowed. Got {k}={v}.")

    # Generate stable case_id if not provided
    if not case_id:
        existing_count = col.count()
        case_id = f"phish_{model_type}_manual_{existing_count:05d}"
    else:
        case_id = str(case_id).strip()
        if not case_id:
            raise ValueError("case_id must be a non-empty string.")

    # Assemble required metadata adhering to ChromaDB scalar types
    timestamp = datetime.now(timezone.utc).isoformat()
    record_meta: Dict[str, Any] = {
        "case_id": case_id,
        "model_type": model_type,
        "feature_names": json.dumps(features),
        "feature_values": json.dumps(validated_vector),
        "source_dataset": str(metadata.get("source_dataset", "runtime_insertion")) if metadata else "runtime_insertion",
        "observed_at": str(metadata.get("observed_at", timestamp)) if metadata else timestamp,
        "source_label": -1,
        "prediction_label": -1,
    }

    # Upsert ensures idempotent insertion without duplicate ID collisions
    col.upsert(
        ids=[case_id],
        embeddings=[[float(x) for x in validated_vector]],
        metadatas=[record_meta]
    )

    return case_id


def get_collection_stats(
    model_type: str,
    persist_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return statistics and metadata for the requested model_type collection.
    """
    validate_model_type(model_type)
    col = get_collection(model_type, persist_dir=persist_dir)
    return {
        "model_type": model_type,
        "collection_name": col.name,
        "count": col.count(),
        "persist_dir": resolve_persist_dir(persist_dir),
    }
