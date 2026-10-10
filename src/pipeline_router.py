"""
Dedicated Backend Pipeline Router for Phishing Detection.

Routes URL requests to either:
- Pipeline A (Full 20-Feature Model): When HTTP GET returns exactly 200 OK with Content-Type text/html.
- Pipeline B (Reduced 10-Feature Model): For all other safe URL outcomes (timeouts, connection errors,
  TLS errors, non-200 status codes, non-HTML media types, missing Content-Type, etc.).

Decision happens BEFORE either feature extraction pipeline is invoked.
"""

import os
import sys
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlparse, urljoin
import requests
import numpy as np

try:
    from src.feature_extractor import _is_safe_url_destination
    from src.classifier import (
        predict_url,
        load_model,
        predict_url_10,
        load_10_feature_model,
        LABEL_DESCRIPTIONS,
    )
except ImportError:
    from feature_extractor import _is_safe_url_destination
    from classifier import (
        predict_url,
        load_model,
        predict_url_10,
        load_10_feature_model,
        LABEL_DESCRIPTIONS,
    )

PIPELINE_FULL = "20-feature"
PIPELINE_REDUCED = "10-feature"

DEFAULT_CHECK_TIMEOUT = 5.0
DEFAULT_MAX_REDIRECTS = 5


@dataclass
class RoutingResult:
    """
    Structured outcome of the routing decision and pipeline execution.
    Supports both attribute access and dictionary subscription.
    """
    pipeline: str
    predicted_label: int
    label_description: str
    phishing_probability: float
    feature_vector: List[int]
    feature_count: int
    routing_reason: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    final_url: Optional[str] = None

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(f"Invalid RoutingResult key: {item!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline": self.pipeline,
            "predicted_label": self.predicted_label,
            "label_description": self.label_description,
            "phishing_probability": self.phishing_probability,
            "feature_vector": self.feature_vector,
            "feature_count": self.feature_count,
            "routing_reason": self.routing_reason,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "final_url": self.final_url,
        }


def check_url_resource(
    url: str,
    timeout: float = DEFAULT_CHECK_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    session: Optional[requests.Session] = None
) -> Tuple[bool, str, Optional[int], Optional[str], str]:
    """
    Perform a controlled, bounded HTTP GET resource check to inspect HTTP status
    and Content-Type header before invoking feature extraction.

    Requirements:
    - Bounded timeout (default 5.0s).
    - Uses streaming request to retrieve headers without reading response body.
    - Explicit redirect handling validating every hop against SSRF security policy.
    - Does NOT download or parse HTML or JavaScript.

    Returns:
        (is_html_200, reason, status_code, content_type, final_url)
        is_html_200: True if final response is 200 OK and Content-Type is text/html; False otherwise.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    cleaned_url = url.strip()
    if "://" not in cleaned_url:
        cleaned_url = "http://" + cleaned_url

    # Enforce initial URL safety policy before network request
    if not _is_safe_url_destination(cleaned_url):
        raise ValueError(f"Invalid or unsafe URL destination: {cleaned_url}")

    client = session or requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishingDetectorRouter/1.0"}
    current_url = cleaned_url

    try:
        for redirect_step in range(max_redirects + 1):
            try:
                resp = client.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                    headers=headers
                )
            except requests.exceptions.Timeout:
                return False, "Request timeout", None, None, current_url
            except requests.exceptions.SSLError as e:
                return False, f"TLS/SSL error: {e}", None, None, current_url
            except requests.exceptions.ConnectionError as e:
                return False, f"Connection failure: {e}", None, None, current_url
            except Exception as e:
                return False, f"HTTP request failed: {e}", None, None, current_url

            status_code = resp.status_code
            content_type = resp.headers.get("Content-Type", "")
            # Close connection stream immediately to prevent downloading body
            resp.close()

            # Inspect redirect responses
            if status_code in (301, 302, 303, 307, 308):
                if redirect_step >= max_redirects:
                    return False, "Exceeded maximum redirects", status_code, content_type, current_url

                location = resp.headers.get("Location")
                if not location:
                    return False, "Redirect missing Location header", status_code, content_type, current_url

                next_url = urljoin(current_url, location.strip())
                # Validate redirect destination against SSRF policy
                if not _is_safe_url_destination(next_url):
                    return False, f"Unsafe redirect destination: {next_url}", status_code, content_type, current_url

                current_url = next_url
                continue

            # Terminal response reached
            media_type = content_type.split(";")[0].strip().lower() if content_type else ""

            if status_code == 200 and media_type == "text/html":
                return True, "200 OK with text/html", status_code, content_type, current_url
            elif status_code != 200:
                return False, f"Non-200 HTTP status ({status_code})", status_code, content_type, current_url
            else:
                return False, f"Non-HTML Content-Type ({content_type or 'missing'})", status_code, content_type, current_url

        return False, "Exceeded maximum redirects", None, None, current_url

    except Exception as e:
        return False, f"Resource check error: {e}", None, None, current_url


def route_url(
    url: str,
    timeout: float = DEFAULT_CHECK_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    model_20_path: Optional[str] = None,
    model_10_path: Optional[str] = None,
    session: Optional[requests.Session] = None
) -> RoutingResult:
    """
    Decide whether to execute Pipeline A (20-feature) or Pipeline B (10-feature)
    for the submitted URL, and invoke the selected pipeline.

    Rules:
    1. Perform initial HTTP GET check first (with bounded timeout and streaming).
    2. If status is exactly 200 OK and media type is text/html -> Pipeline A (20-feature).
    3. In all other safe cases -> Pipeline B (10-feature).
    4. Unsafe URLs are rejected before making any request.

    Returns:
        RoutingResult containing the chosen pipeline name, predicted class,
        phishing probability, feature vector, and decision metadata.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    cleaned_url = url.strip()

    # Step 1: Resource check first
    is_html_200, reason, status_code, content_type, final_url = check_url_resource(
        cleaned_url,
        timeout=timeout,
        max_redirects=max_redirects,
        session=session
    )

    # Step 2: Route to selected pipeline
    if is_html_200:
        # Route A: Full-feature pipeline (20 features)
        try:
            pred_label, vector = predict_url(cleaned_url, model_path=model_20_path)
            model_20 = load_model(model_path=model_20_path)
            sample_2d = np.array([vector], dtype=int)
            probs = model_20.predict_proba(sample_2d)
            classes_list = list(model_20.classes_)
            pos_idx = classes_list.index(1) if 1 in classes_list else 1
            phishing_prob = float(probs[0][pos_idx])
        except Exception as e:
            raise RuntimeError(f"Pipeline A (20-feature) execution failed: {e}") from e

        return RoutingResult(
            pipeline=PIPELINE_FULL,
            predicted_label=pred_label,
            label_description=LABEL_DESCRIPTIONS.get(pred_label, "Unknown"),
            phishing_probability=phishing_prob,
            feature_vector=vector,
            feature_count=20,
            routing_reason=reason,
            status_code=status_code,
            content_type=content_type,
            final_url=final_url
        )
    else:
        # Route B: Reduced-feature pipeline (10 features)
        try:
            pred_label, phishing_prob, vector = predict_url_10(
                cleaned_url,
                model_path=model_10_path,
                return_proba=True
            )
        except Exception as e:
            raise RuntimeError(f"Pipeline B (10-feature) execution failed: {e}") from e

        return RoutingResult(
            pipeline=PIPELINE_REDUCED,
            predicted_label=pred_label,
            label_description=LABEL_DESCRIPTIONS.get(pred_label, "Unknown"),
            phishing_probability=phishing_prob,
            feature_vector=vector,
            feature_count=10,
            routing_reason=reason,
            status_code=status_code,
            content_type=content_type,
            final_url=final_url
        )
