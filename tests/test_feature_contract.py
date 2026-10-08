"""
Tests for the Authoritative 20-Feature Vector Contract.
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import (
    FEATURE_NAMES,
    ALLOWED_VALUES,
    feature_index,
    feature_name_at,
    validate_feature_vector,
)


class TestFeatureContract(unittest.TestCase):

    def test_1_feature_count(self):
        """Test that there are exactly 20 feature names."""
        self.assertEqual(len(FEATURE_NAMES), 20)

    def test_2_exact_feature_order(self):
        """Test that feature names are in the exact required order."""
        expected_order = (
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
        self.assertEqual(FEATURE_NAMES, expected_order)

    def test_3_every_feature_has_allowed_values(self):
        """Test that every feature has an allowed-value definition."""
        for feat in FEATURE_NAMES:
            self.assertIn(feat, ALLOWED_VALUES)

    def test_4_allowed_values_match_specification(self):
        """Test that allowed values exactly match the specification."""
        expected_allowed = {
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
        self.assertEqual(ALLOWED_VALUES, expected_allowed)

    def test_5_feature_index_having_ip_address(self):
        """Test feature_index('having_IP_Address') returns 0."""
        self.assertEqual(feature_index("having_IP_Address"), 0)

    def test_6_feature_index_rightclick(self):
        """Test feature_index('RightClick') returns 19."""
        self.assertEqual(feature_index("RightClick"), 19)

    def test_7_feature_name_at_1(self):
        """Test feature_name_at(1) returns 'having_IP_Address'."""
        self.assertEqual(feature_name_at(1), "having_IP_Address")

    def test_8_feature_name_at_20(self):
        """Test feature_name_at(20) returns 'RightClick'."""
        self.assertEqual(feature_name_at(20), "RightClick")

    def test_position_out_of_bounds(self):
        """Test that positions outside 1-20 raise ValueError."""
        with self.assertRaises(ValueError):
            feature_name_at(0)
        with self.assertRaises(ValueError):
            feature_name_at(21)

    def test_feature_index_unknown(self):
        """Test that unknown feature names raise ValueError."""
        with self.assertRaises(ValueError):
            feature_index("Unknown_Feature")

    def test_9_valid_20_value_vector_accepted(self):
        """Test that a valid 20-value vector is accepted."""
        valid_vector = [1] * 20
        self.assertTrue(validate_feature_vector(valid_vector))

    def test_10_vector_19_values_rejected(self):
        """Test that a vector with 19 values is rejected."""
        vector_19 = [1] * 19
        with self.assertRaises(ValueError):
            validate_feature_vector(vector_19)

    def test_11_vector_21_values_rejected(self):
        """Test that a vector with 21 values is rejected."""
        vector_21 = [1] * 21
        with self.assertRaises(ValueError):
            validate_feature_vector(vector_21)

    def test_12_vector_with_invalid_value_rejected(self):
        """Test that a vector containing an invalid value for a feature is rejected."""
        invalid_vector = [2] + [1] * 19  # 2 is invalid for having_IP_Address
        with self.assertRaises(ValueError):
            validate_feature_vector(invalid_vector)

    def test_13_result_not_in_feature_names(self):
        """Test that Result is not included in FEATURE_NAMES."""
        self.assertNotIn("Result", FEATURE_NAMES)


if __name__ == "__main__":
    unittest.main()
