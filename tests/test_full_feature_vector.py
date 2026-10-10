"""
Automated unit tests for the complete 20-feature vector extractor:
- extract_features(url)
- Exact 20-feature ordering (Positions 1 to 20)
- Feature vector contract compliance
- Rejection of invalid inputs and invalid feature values
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import (
    FEATURE_NAMES,
    ALLOWED_VALUES,
    validate_feature_vector,
)
from src.feature_extractor import extract_features


class TestFullFeatureVector(unittest.TestCase):

    def test_empty_or_whitespace_url_raises_value_error(self):
        with self.assertRaises(ValueError):
            extract_features("")
        with self.assertRaises(ValueError):
            extract_features("   ")
        with self.assertRaises(ValueError):
            extract_features(None)

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_redirect")
    def test_extract_features_mocked_webpage_returns_valid_20_vector(
        self,
        mock_redirect,
        mock_port,
        mock_ssl,
        mock_fetch,
    ):
        mock_fetch.return_value = (
            "<html><head><title>Test</title></head><body><a href='/home'>Link</a></body></html>",
            "https://example.com/home",
        )
        mock_ssl.return_value = 1
        mock_port.return_value = 1
        mock_redirect.return_value = 0

        vector = extract_features("https://example.com/test")

        # 1. Exactly 20 values returned
        self.assertEqual(len(vector), 20)

        # 2. Vector is a list of integers
        self.assertIsInstance(vector, list)
        for v in vector:
            self.assertIsInstance(v, int)

        # 3. Validation against authoritative contract passes
        self.assertTrue(validate_feature_vector(vector))

        # 4. Result is not included
        self.assertEqual(len(vector), len(FEATURE_NAMES))
        self.assertNotIn("Result", FEATURE_NAMES)

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_redirect")
    def test_vector_positions_match_authoritative_feature_names(
        self,
        mock_redirect,
        mock_port,
        mock_ssl,
        mock_fetch,
    ):
        mock_fetch.return_value = ("<html><body></body></html>", "https://example.com/")
        mock_ssl.return_value = 1
        mock_port.return_value = 1
        mock_redirect.return_value = 0

        vector = extract_features("https://example.com")

        # Ensure every element at position i conforms to ALLOWED_VALUES[FEATURE_NAMES[i]]
        for i, feat_name in enumerate(FEATURE_NAMES):
            val = vector[i]
            allowed = ALLOWED_VALUES[feat_name]
            self.assertIn(
                val,
                allowed,
                f"Value {val} for feature {feat_name} at position {i+1} not in {allowed}",
            )

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_redirect")
    @patch("src.feature_extractor.extract_having_ip_address")
    def test_invalid_feature_value_rejected_by_validation(
        self,
        mock_ip,
        mock_redirect,
        mock_port,
        mock_ssl,
        mock_fetch,
    ):
        mock_fetch.return_value = ("<html></html>", "https://example.com/")
        mock_ssl.return_value = 1
        mock_port.return_value = 1
        mock_redirect.return_value = 0
        # Illegal value (99 is not in {-1, 1})
        mock_ip.return_value = 99

        with self.assertRaises(ValueError) as ctx:
            extract_features("https://example.com")
        self.assertIn("Invalid value", str(ctx.exception))

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_having_ip_address")
    @patch("src.feature_extractor.extract_url_length")
    @patch("src.feature_extractor.extract_shortining_service")
    @patch("src.feature_extractor.extract_having_at_symbol")
    @patch("src.feature_extractor.extract_double_slash_redirecting")
    @patch("src.feature_extractor.extract_prefix_suffix")
    @patch("src.feature_extractor.extract_having_sub_domain")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_https_token")
    @patch("src.feature_extractor.extract_favicon")
    @patch("src.feature_extractor.extract_request_url")
    @patch("src.feature_extractor.extract_url_of_anchor")
    @patch("src.feature_extractor.extract_links_in_tags")
    @patch("src.feature_extractor.extract_sfh")
    @patch("src.feature_extractor.extract_submitting_to_email")
    @patch("src.feature_extractor.extract_iframe")
    @patch("src.feature_extractor.extract_redirect")
    @patch("src.feature_extractor.extract_on_mouseover")
    @patch("src.feature_extractor.extract_right_click")
    def test_delegation_to_existing_feature_functions_in_order(
        self,
        mock_right_click,
        mock_mouseover,
        mock_redirect,
        mock_iframe,
        mock_email,
        mock_sfh,
        mock_links,
        mock_anchor,
        mock_request,
        mock_favicon,
        mock_https_token,
        mock_port,
        mock_ssl,
        mock_subdomain,
        mock_prefix,
        mock_double_slash,
        mock_at,
        mock_short,
        mock_len,
        mock_ip,
        mock_fetch,
    ):
        mock_fetch.return_value = ("<html>test</html>", "https://final.example.com")
        mock_ip.return_value = 1
        mock_len.return_value = 1
        mock_short.return_value = 1
        mock_at.return_value = 1
        mock_double_slash.return_value = 1
        mock_prefix.return_value = 1
        mock_subdomain.return_value = 1
        mock_ssl.return_value = 1
        mock_port.return_value = 1
        mock_https_token.return_value = 1
        mock_favicon.return_value = 1
        mock_request.return_value = 1
        mock_anchor.return_value = 1
        mock_links.return_value = 1
        mock_sfh.return_value = 1
        mock_email.return_value = 1
        mock_iframe.return_value = 1
        mock_redirect.return_value = 0
        mock_mouseover.return_value = 1
        mock_right_click.return_value = 1

        test_url = "https://example.com/login"
        vec = extract_features(test_url)

        # Confirm all 20 feature functions were called
        mock_ip.assert_called_once_with(test_url)
        mock_len.assert_called_once_with(test_url)
        mock_short.assert_called_once_with(test_url)
        mock_at.assert_called_once_with(test_url)
        mock_double_slash.assert_called_once_with(test_url)
        mock_prefix.assert_called_once_with(test_url)
        mock_subdomain.assert_called_once_with(test_url)
        mock_ssl.assert_called_once_with(test_url)
        mock_port.assert_called_once_with(test_url)
        mock_https_token.assert_called_once_with(test_url)

        # HTML/content features called with html and final_url
        mock_favicon.assert_called_once_with("<html>test</html>", "https://final.example.com")
        mock_request.assert_called_once_with("<html>test</html>", "https://final.example.com")
        mock_anchor.assert_called_once_with("<html>test</html>", "https://final.example.com")
        mock_links.assert_called_once_with("<html>test</html>", "https://final.example.com")
        mock_sfh.assert_called_once_with("<html>test</html>", "https://final.example.com")
        mock_iframe.assert_called_once_with("<html>test</html>")

        # Section 2 redirect
        mock_redirect.assert_called_once_with(test_url)

        # Section 4 JS features called with html, final_url, and session
        self.assertEqual(mock_email.call_count, 1)
        self.assertEqual(mock_mouseover.call_count, 1)
        self.assertEqual(mock_right_click.call_count, 1)

        # Returned vector matches the mock values
        expected = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1]
        self.assertEqual(vec, expected)

    @patch("src.feature_extractor.fetch_webpage")
    def test_network_fetch_failure_falls_back_safely_to_valid_vector(self, mock_fetch):
        # Simulate network failure during fetch_webpage
        mock_fetch.side_effect = Exception("Network unreachable")

        with patch("src.feature_extractor.extract_ssl_final_state", return_value=-1), \
             patch("src.feature_extractor.extract_port", return_value=1), \
             patch("src.feature_extractor.extract_redirect", return_value=-1):
            vector = extract_features("https://nonexistent-domain.xyz")
            self.assertEqual(len(vector), 20)
            self.assertTrue(validate_feature_vector(vector))


if __name__ == "__main__":
    unittest.main()
