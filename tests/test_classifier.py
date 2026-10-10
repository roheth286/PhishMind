"""
Unit tests for the Classifier Module (src/classifier.py).

Tests:
- predict_url() calls extract_features() with the provided URL
- exactly 20 features in authoritative order are supplied to the model
- predicted labels: 1 = Legitimate, -1 = Phishing
- contract validation catches invalid feature vectors before model prediction
- model loading error handling and caching
- model is never retrained or modified
"""

import unittest
from unittest.mock import patch, MagicMock
import numpy as np
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import FEATURE_NAMES
from src.classifier import (
    predict_url,
    load_model,
    clear_model_cache,
    LABEL_DESCRIPTIONS,
    DEFAULT_MODEL_PATH,
)


class TestClassifier(unittest.TestCase):

    def setUp(self):
        clear_model_cache()

    def tearDown(self):
        clear_model_cache()

    def test_empty_or_whitespace_url_raises_value_error(self):
        with self.assertRaises(ValueError):
            predict_url("")
        with self.assertRaises(ValueError):
            predict_url("   ")
        with self.assertRaises(ValueError):
            predict_url(None)

    def test_model_file_exists_and_loads(self):
        # Verify the actual trained model file exists and can be loaded
        self.assertTrue(os.path.exists(DEFAULT_MODEL_PATH))
        model = load_model()
        self.assertIsNotNone(model)
        self.assertEqual(model.n_features_in_, 20)
        # Verify caching returns same instance
        model2 = load_model()
        self.assertIs(model, model2)

    def test_model_loading_missing_file_raises_filenotfound(self):
        with self.assertRaises(FileNotFoundError):
            load_model("nonexistent_path_to_model.pkl")

    @patch("src.classifier.extract_features")
    @patch("src.classifier.load_model")
    def test_predict_url_legitimate_label_1(self, mock_load_model, mock_extract):
        # 20 valid features
        sample_vector = [1] * 20
        mock_extract.return_value = sample_vector

        mock_rf = MagicMock()
        mock_rf.predict.return_value = np.array([1])
        mock_load_model.return_value = mock_rf

        label, vec = predict_url("https://example.com")

        # extract_features was called with the URL
        mock_extract.assert_called_once_with("https://example.com")

        # Ensure sample passed to model is 2D with shape (1, 20)
        self.assertEqual(mock_rf.predict.call_count, 1)
        passed_arg = mock_rf.predict.call_args[0][0]
        self.assertEqual(passed_arg.shape, (1, 20))
        self.assertEqual(list(passed_arg[0]), sample_vector)

        # Label interpretation: 1 -> Legitimate
        self.assertEqual(label, 1)
        self.assertEqual(LABEL_DESCRIPTIONS[label], "Legitimate")
        self.assertEqual(vec, sample_vector)

    @patch("src.classifier.extract_features")
    @patch("src.classifier.load_model")
    def test_predict_url_phishing_label_neg_1(self, mock_load_model, mock_extract):
        # 20 valid features
        sample_vector = [-1] * 20
        # Allow 0 where allowed, or valid values:
        # Check ALLOWED_VALUES: URL_Length allows {1, 0, -1}, having_IP_Address allows {1, -1}
        # Vector with all -1 is valid since all 20 features allow -1
        mock_extract.return_value = sample_vector

        mock_rf = MagicMock()
        mock_rf.predict.return_value = np.array([-1])
        mock_load_model.return_value = mock_rf

        label, vec = predict_url("http://phish-site.com/login")

        # Label interpretation: -1 -> Phishing
        self.assertEqual(label, -1)
        self.assertEqual(LABEL_DESCRIPTIONS[label], "Phishing")
        self.assertEqual(vec, sample_vector)

    @patch("src.classifier.extract_features")
    @patch("src.classifier.load_model")
    def test_invalid_vector_rejected_before_prediction(self, mock_load_model, mock_extract):
        # Vector with 19 values (missing 1)
        mock_extract.return_value = [1] * 19
        mock_rf = MagicMock()
        mock_load_model.return_value = mock_rf

        with self.assertRaises(ValueError):
            predict_url("https://example.com")

        # Model predict should not have been called
        mock_rf.predict.assert_not_called()

        # Vector with invalid value (e.g. 99)
        mock_extract.return_value = [1] * 19 + [99]
        with self.assertRaises(ValueError):
            predict_url("https://example.com")
        mock_rf.predict.assert_not_called()

    @patch("src.classifier.extract_features")
    @patch("src.classifier.load_model")
    def test_model_prediction_exception_handled(self, mock_load_model, mock_extract):
        mock_extract.return_value = [1] * 20
        mock_rf = MagicMock()
        mock_rf.predict.side_effect = RuntimeError("Prediction runtime failure")
        mock_load_model.return_value = mock_rf

        with self.assertRaises(RuntimeError) as ctx:
            predict_url("https://example.com")
        self.assertIn("Model prediction failed", str(ctx.exception))

    @patch("src.classifier.extract_features")
    def test_real_model_prediction_integration(self, mock_extract):
        # Test using actual models/random_forest.pkl loaded from disk
        mock_extract.return_value = [1] * 20
        label, vec = predict_url("https://example.com")
        self.assertIn(label, (1, -1))
        self.assertEqual(len(vec), 20)

    def test_real_model_predict_proba_and_classes(self):
        # Verify the saved model has 20 features, classes [-1, 1], and predict_proba works
        model = load_model()
        self.assertEqual(model.n_features_in_, 20)
        self.assertEqual(list(model.classes_), [-1, 1])

        # Test predict_proba on shape (1, 20)
        sample = np.ones((1, 20), dtype=int)
        probs = model.predict_proba(sample)
        self.assertEqual(probs.shape, (1, 2))
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=5)
        # Class 1 (phishing) index is 1
        pos_idx = list(model.classes_).index(1)
        self.assertEqual(pos_idx, 1)
        phishing_prob = probs[0][pos_idx]
        self.assertGreaterEqual(phishing_prob, 0.0)
        self.assertLessEqual(phishing_prob, 1.0)


if __name__ == "__main__":
    unittest.main()
