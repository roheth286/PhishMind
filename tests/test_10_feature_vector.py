"""
Unit and integration tests for the 10-Feature Vector Maker and 10-Feature Inference Pipeline:
- extract_10_features(url)
- validate_10_feature_vector(vector)
- load_10_feature_model(model_path)
- predict_url_10(url) and predict_proba_url_10(url)
- Error behavior preservation for SSLfinal_State and port
- Verification that the 20-feature pipeline remains functional and unchanged
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import numpy as np

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import (
    FEATURE_NAMES,
    FEATURE_NAMES_10,
    ALLOWED_VALUES,
    validate_feature_vector,
    validate_10_feature_vector,
)
from src.feature_extractor import extract_features, extract_10_features
from src.classifier import (
    load_model,
    load_10_feature_model,
    clear_model_cache,
    predict_url,
    predict_url_10,
    predict_proba_url_10,
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_10_PATH,
)


class Test10FeatureVectorMaker(unittest.TestCase):

    def setUp(self):
        clear_model_cache()

    def tearDown(self):
        clear_model_cache()

    def test_empty_or_whitespace_url_raises_value_error(self):
        with self.assertRaises(ValueError):
            extract_10_features("")
        with self.assertRaises(ValueError):
            extract_10_features("   ")
        with self.assertRaises(ValueError):
            extract_10_features(None)

        with self.assertRaises(ValueError):
            predict_url_10("")
        with self.assertRaises(ValueError):
            predict_url_10("   ")
        with self.assertRaises(ValueError):
            predict_url_10(None)

    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_https_token")
    @patch("src.feature_extractor.extract_having_sub_domain")
    @patch("src.feature_extractor.extract_prefix_suffix")
    @patch("src.feature_extractor.extract_double_slash_redirecting")
    @patch("src.feature_extractor.extract_having_at_symbol")
    @patch("src.feature_extractor.extract_shortining_service")
    @patch("src.feature_extractor.extract_url_length")
    @patch("src.feature_extractor.extract_having_ip_address")
    def test_extract_10_features_exact_values_and_ordering(
        self,
        mock_ip,
        mock_len,
        mock_short,
        mock_at,
        mock_slash,
        mock_prefix,
        mock_subdomain,
        mock_https_token,
        mock_ssl,
        mock_port,
    ):
        # Configure mock return values for each feature
        mock_ip.return_value = 1               # 1. having_IP_Address
        mock_len.return_value = 0              # 2. URL_Length
        mock_short.return_value = 1            # 3. Shortining_Service
        mock_at.return_value = -1              # 4. having_At_Symbol
        mock_slash.return_value = 1            # 5. double_slash_redirecting
        mock_prefix.return_value = -1          # 6. Prefix_Suffix
        mock_subdomain.return_value = 0        # 7. having_Sub_Domain
        mock_https_token.return_value = 1      # 8. HTTPS_token
        mock_ssl.return_value = -1             # 9. SSLfinal_State
        mock_port.return_value = 1             # 10. port

        vector = extract_10_features("https://example.com/test")

        # 1. Exactly 10 values
        self.assertEqual(len(vector), 10)
        self.assertEqual(len(vector), len(FEATURE_NAMES_10))

        # 2. Exact values in exact sequence
        expected_vector = [1, 0, 1, -1, 1, -1, 0, 1, -1, 1]
        self.assertEqual(vector, expected_vector)

        # 3. Target Result is strictly NOT included
        self.assertNotIn("Result", FEATURE_NAMES_10)

        # 4. Validated by 10-feature contract
        self.assertTrue(validate_10_feature_vector(vector))

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_https_token")
    @patch("src.feature_extractor.extract_having_sub_domain")
    @patch("src.feature_extractor.extract_prefix_suffix")
    @patch("src.feature_extractor.extract_double_slash_redirecting")
    @patch("src.feature_extractor.extract_having_at_symbol")
    @patch("src.feature_extractor.extract_shortining_service")
    @patch("src.feature_extractor.extract_url_length")
    @patch("src.feature_extractor.extract_having_ip_address")
    def test_extract_10_features_does_not_download_webpage_content(
        self,
        mock_ip,
        mock_len,
        mock_short,
        mock_at,
        mock_slash,
        mock_prefix,
        mock_subdomain,
        mock_https_token,
        mock_ssl,
        mock_port,
        mock_fetch,
    ):
        mock_ip.return_value = 1
        mock_len.return_value = 1
        mock_short.return_value = 1
        mock_at.return_value = 1
        mock_slash.return_value = 1
        mock_prefix.return_value = 1
        mock_subdomain.return_value = 1
        mock_https_token.return_value = 1
        mock_ssl.return_value = 1
        mock_port.return_value = 1

        vector = extract_10_features("https://example.com")
        self.assertEqual(len(vector), 10)

        # Confirm fetch_webpage is NEVER called for 10-feature extraction
        mock_fetch.assert_not_called()

    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_ssl_final_state")
    def test_ssl_and_port_error_behavior_preserved(self, mock_ssl, mock_port):
        # When TLS handshake fails and port check fails, both return -1
        mock_ssl.return_value = -1
        mock_port.return_value = -1

        vector = extract_10_features("http://inaccessible-domain.org")
        self.assertEqual(vector[8], -1)  # SSLfinal_State (position 9)
        self.assertEqual(vector[9], -1)  # port (position 10)

    def test_contract_validation_rejects_invalid_vector(self):
        # Length 9 (missing 1)
        with self.assertRaises(ValueError):
            validate_10_feature_vector([1] * 9)

        # Length 11 (extra 1)
        with self.assertRaises(ValueError):
            validate_10_feature_vector([1] * 11)

        # Invalid value (99)
        with self.assertRaises(ValueError):
            validate_10_feature_vector([1] * 9 + [99])

        # Boolean (rejected even though bool is subclass of int)
        with self.assertRaises(ValueError):
            validate_10_feature_vector([1] * 9 + [True])

        # Cross-validation: 10-feature vector rejected by 20-feature validator
        with self.assertRaises(ValueError):
            validate_feature_vector([1] * 10)

        # Cross-validation: 20-feature vector rejected by 10-feature validator
        with self.assertRaises(ValueError):
            validate_10_feature_vector([1] * 20)

    def test_10_feature_model_loading_and_shape(self):
        self.assertTrue(os.path.exists(DEFAULT_MODEL_10_PATH))
        model_10 = load_10_feature_model()
        self.assertIsNotNone(model_10)
        self.assertEqual(model_10.n_features_in_, 10)
        self.assertEqual(list(model_10.classes_), [-1, 1])

        # Verify caching returns same instance
        model_10_again = load_10_feature_model()
        self.assertIs(model_10, model_10_again)

    @patch("src.classifier.extract_10_features")
    def test_predict_url_10_real_model_inference(self, mock_extract):
        # 10 valid features (all 1s)
        sample_vector = [1] * 10
        mock_extract.return_value = sample_vector

        # Predict with default return_proba=True
        label, prob, vec = predict_url_10("https://example.com")
        self.assertIn(label, (1, -1))
        self.assertIsInstance(prob, float)
        self.assertGreaterEqual(prob, 0.0)
        self.assertLessEqual(prob, 1.0)
        self.assertEqual(vec, sample_vector)

        # Predict with return_proba=False
        res_label, res_vec = predict_url_10("https://example.com", return_proba=False)
        self.assertEqual(res_label, label)
        self.assertEqual(res_vec, sample_vector)

        # Helper predict_proba_url_10
        prob_only = predict_proba_url_10("https://example.com")
        self.assertEqual(prob_only, prob)

    @patch("src.feature_extractor.fetch_webpage")
    @patch("src.feature_extractor.extract_ssl_final_state")
    @patch("src.feature_extractor.extract_port")
    @patch("src.feature_extractor.extract_redirect")
    def test_20_feature_vector_maker_and_model_remain_functional(
        self,
        mock_redirect,
        mock_port,
        mock_ssl,
        mock_fetch,
    ):
        # Ensure the existing 20-feature extractor continues working unchanged
        mock_fetch.return_value = ("<html><body></body></html>", "https://example.com/")
        mock_ssl.return_value = 1
        mock_port.return_value = 1
        mock_redirect.return_value = 0

        vec_20 = extract_features("https://example.com")
        self.assertEqual(len(vec_20), 20)
        self.assertTrue(validate_feature_vector(vec_20))

        # Ensure the 20-feature model loads and predicts properly
        model_20 = load_model()
        self.assertEqual(model_20.n_features_in_, 20)

        label_20, return_vec_20 = predict_url("https://example.com")
        self.assertIn(label_20, (1, -1))
        self.assertEqual(len(return_vec_20), 20)


if __name__ == "__main__":
    unittest.main()
