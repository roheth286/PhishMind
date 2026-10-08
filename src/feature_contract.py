"""
Authoritative 20-Feature Vector Contract for Phishing Detection.

This module defines the single source of truth for:
- The exact 20-feature ordering (Position 1 to 20).
- The exact allowed values for each feature.
- Validation and lookup utilities for 20-dimensional feature vectors.
"""

from typing import Any, Dict, Sequence, Set, Tuple

# Exact authoritative feature names in exact order (Positions 1 to 20)
# 'Result' is the target label and is strictly NOT included here.
FEATURE_NAMES: Tuple[str, ...] = (
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

# Exact authoritative mapping of allowed values per feature
ALLOWED_VALUES: Dict[str, Set[int]] = {
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

_FEATURE_TO_INDEX: Dict[str, int] = {name: idx for idx, name in enumerate(FEATURE_NAMES)}


def feature_index(feature_name: str) -> int:
    """
    Return the zero-based Python index (0 to 19) for the given feature name.

    Raises:
        ValueError: If feature_name is not in FEATURE_NAMES.
    """
    if feature_name not in _FEATURE_TO_INDEX:
        raise ValueError(f"Unknown feature name: {feature_name!r}")
    return _FEATURE_TO_INDEX[feature_name]


def feature_name_at(position: int) -> str:
    """
    Accept the 1-based human-readable position (1 to 20) and return the feature name.

    Raises:
        ValueError: If position is outside 1-20.
    """
    if not isinstance(position, int) or position < 1 or position > len(FEATURE_NAMES):
        raise ValueError(f"Position must be an integer between 1 and {len(FEATURE_NAMES)}, got {position!r}")
    return FEATURE_NAMES[position - 1]


def validate_feature_vector(vector: Sequence[Any]) -> bool:
    """
    Validate a live 20-dimensional feature vector.

    Requirements:
    - vector must contain exactly 20 values.
    - values must be validated according to their corresponding feature position.
    - reject invalid values or lengths.

    Returns:
        True: if the vector is valid.

    Raises:
        ValueError: if the vector has invalid length or contains invalid values.
    """
    if len(vector) != len(FEATURE_NAMES):
        raise ValueError(
            f"Expected exactly {len(FEATURE_NAMES)} features in vector, got {len(vector)}"
        )

    for idx, (feature_name, val) in enumerate(zip(FEATURE_NAMES, vector)):
        allowed = ALLOWED_VALUES[feature_name]
        # Reject booleans (since in Python bool is a subclass of int: isinstance(True, int) is True)
        if isinstance(val, bool) or val not in allowed:
            raise ValueError(
                f"Invalid value {val!r} for feature {feature_name!r} at position {idx + 1}. "
                f"Allowed values: {sorted(list(allowed))}"
            )

    return True
