"""
URL validation utility for the Phishing Detection Streamlit application.

Performs lightweight frontend input validation strictly adhering to specifications:
1. Trim leading and trailing whitespace.
2. Reject the input if it contains any whitespace characters internally.
3. Remove a leading http:// or https://, case-insensitively.
4. Extract the host by taking the portion before the first '/', '?', or '#'.
5. Accept the host if it is a valid IP address, or if it contains at least one dot
   and has a final hostname label of at least two characters.
6. Otherwise, reject as invalid URL.
"""

import ipaddress
import re
from typing import Tuple


def validate_url_format(raw_input: str) -> Tuple[bool, str]:
    """
    Validates user input according to the lightweight frontend specification.

    Returns:
        (is_valid, error_message_or_cleaned_url)
        If valid: (True, cleaned_original_url_string)
        If invalid: (False, "URL not valid")
    """
    if not isinstance(raw_input, str):
        return False, "URL not valid"

    # Step 1: Trim leading and trailing whitespace
    trimmed = raw_input.strip()
    if not trimmed:
        return False, "URL not valid"

    # Step 2: Reject the input if it contains any whitespace characters internally
    if any(c.isspace() for c in trimmed):
        return False, "URL not valid"

    # Step 3: Remove leading http:// or https://, case-insensitively
    working_str = trimmed
    lower_str = working_str.lower()
    if lower_str.startswith("http://"):
        working_str = working_str[7:]
    elif lower_str.startswith("https://"):
        working_str = working_str[8:]

    # Step 4: Extract the host by taking the portion before the first '/', '?', or '#'
    # Also strip port if specified (e.g. host:port)
    host_part = re.split(r"[/?#]", working_str)[0]

    if not host_part:
        return False, "URL not valid"

    # If host has port e.g. 192.168.1.1:8080 or example.com:443
    # Note: IPv6 bracketed hosts e.g. [::1]:80
    if host_part.startswith("[") and "]" in host_part:
        host_to_check = host_part[1:host_part.index("]")]
    elif ":" in host_part:
        host_to_check = host_part.split(":")[0]
    else:
        host_to_check = host_part

    if not host_to_check:
        return False, "URL not valid"

    # Step 5: Check if host is valid IP address (using standard ipaddress library)
    try:
        ipaddress.ip_address(host_to_check)
        # Valid IP address host
        return True, trimmed
    except ValueError:
        pass

    # Step 5b: Check if host contains at least one dot and has a final hostname label >= 2 chars
    # Ensure no leading/trailing dots or empty labels
    labels = host_to_check.split(".")
    if len(labels) < 2:
        return False, "URL not valid"

    # Every label should be non-empty and valid hostname characters (alphanumeric, hyphens)
    for label in labels:
        if not label:
            return False, "URL not valid"
        # Check label doesn't start or end with hyphen
        if label.startswith("-") or label.endswith("-"):
            return False, "URL not valid"

    final_label = labels[-1]
    if len(final_label) < 2:
        return False, "URL not valid"

    # All checks passed
    return True, trimmed
