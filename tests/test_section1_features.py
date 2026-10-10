"""
Tests for Section 1 Features (URL String / URL Structure).
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import ALLOWED_VALUES
from src.feature_extractor import (
    extract_having_ip_address,
    extract_url_length,
    extract_shortining_service,
    extract_having_at_symbol,
    extract_double_slash_redirecting,
    extract_prefix_suffix,
    extract_having_sub_domain,
    extract_https_token,
)


class TestSection1Features(unittest.TestCase):

    def test_feature_1_having_ip_address(self):
        # Normal hostnames -> 1
        self.assertEqual(extract_having_ip_address("https://paypal.com/login"), 1)
        self.assertEqual(extract_having_ip_address("http://example.org/test"), 1)
        # IPv4 addresses -> -1
        self.assertEqual(extract_having_ip_address("http://192.168.1.1/login"), -1)
        self.assertEqual(extract_having_ip_address("http://127.0.0.1:8080/path"), -1)
        # Hexadecimal IP representations -> -1
        self.assertEqual(extract_having_ip_address("http://0x58.0xCC.0xCA.0x62/test"), -1)
        self.assertEqual(extract_having_ip_address("http://0x7f000001/login"), -1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["having_IP_Address"])

    def test_feature_2_url_length(self):
        # length < 54 -> 1
        url_53 = "http://example.com/" + "a" * (53 - len("http://example.com/"))
        self.assertEqual(len(url_53), 53)
        self.assertEqual(extract_url_length(url_53), 1)

        # 54 <= length <= 75 -> 0
        url_54 = "http://example.com/" + "a" * (54 - len("http://example.com/"))
        self.assertEqual(len(url_54), 54)
        self.assertEqual(extract_url_length(url_54), 0)

        url_75 = "http://example.com/" + "a" * (75 - len("http://example.com/"))
        self.assertEqual(len(url_75), 75)
        self.assertEqual(extract_url_length(url_75), 0)

        # length > 75 -> -1
        url_76 = "http://example.com/" + "a" * (76 - len("http://example.com/"))
        self.assertEqual(len(url_76), 76)
        self.assertEqual(extract_url_length(url_76), -1)

        # Validate against contract
        for val in [1, 0, -1]:
            self.assertIn(val, ALLOWED_VALUES["URL_Length"])

    def test_feature_3_shortining_service(self):
        # Shortening domains -> -1
        self.assertEqual(extract_shortining_service("https://bit.ly/19DXSk4"), -1)
        self.assertEqual(extract_shortining_service("https://BIT.LY/19DXSk4"), -1)
        self.assertEqual(extract_shortining_service("https://tinyurl.com/example"), -1)
        self.assertEqual(extract_shortining_service("http://tinyurl.com/foo"), -1)
        # Ordinary domain -> 1
        self.assertEqual(extract_shortining_service("https://example.com/login"), 1)
        self.assertEqual(extract_shortining_service("https://google.com/search"), 1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["Shortining_Service"])

    def test_feature_4_having_at_symbol(self):
        # URL without @ -> 1
        self.assertEqual(extract_having_at_symbol("https://example.com/login"), 1)
        # URL containing @ -> -1
        self.assertEqual(extract_having_at_symbol("http://example.com@evil.com/login"), -1)
        self.assertEqual(extract_having_at_symbol("https://example.com/path?user=test@domain.com"), -1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["having_At_Symbol"])

    def test_feature_5_double_slash_redirecting(self):
        # Normal http URL -> 1 (first // is at pos 5 or 6 <= 7)
        self.assertEqual(extract_double_slash_redirecting("http://example.com/login"), 1)
        # Normal https URL -> 1 (first // is at pos 6 <= 7)
        self.assertEqual(extract_double_slash_redirecting("https://example.com/login"), 1)
        # Additional // later in URL -> -1
        self.assertEqual(extract_double_slash_redirecting("http://example.com//login"), -1)
        self.assertEqual(extract_double_slash_redirecting("https://example.com/path//login"), -1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["double_slash_redirecting"])

    def test_feature_6_prefix_suffix(self):
        # Domain without '-' -> 1
        self.assertEqual(extract_prefix_suffix("https://paypal.com/login"), 1)
        # Domain containing '-' -> -1
        self.assertEqual(extract_prefix_suffix("https://pay-pal.com/login"), -1)
        self.assertEqual(extract_prefix_suffix("https://sub-domain.example.com"), -1)
        # '-' only in path -> 1
        self.assertEqual(extract_prefix_suffix("https://paypal.com/my-account/login"), 1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["Prefix_Suffix"])

    def test_feature_7_having_sub_domain(self):
        # Exactly 1 remaining dot -> 1 (e.g. example.com, www.example.com, example.co.uk)
        # example.com -> 1 dot
        self.assertEqual(extract_having_sub_domain("http://example.com"), 1)
        # www.example.com -> omit www -> example.com -> 1 dot
        self.assertEqual(extract_having_sub_domain("http://www.example.com"), 1)
        # example.co.uk -> omit uk (ccTLD) -> example.co -> 1 dot
        self.assertEqual(extract_having_sub_domain("http://example.co.uk"), 1)

        # Exactly 2 remaining dots -> 0 (e.g. sub.example.com, www.sub.example.com)
        # sub.example.com -> 2 dots -> 0
        self.assertEqual(extract_having_sub_domain("http://sub.example.com"), 0)
        # www.sub.example.com -> omit www -> sub.example.com -> 2 dots -> 0
        self.assertEqual(extract_having_sub_domain("http://www.sub.example.com"), 0)
        # sub.example.co.uk -> omit uk -> sub.example.co -> 2 dots -> 0
        self.assertEqual(extract_having_sub_domain("http://sub.example.co.uk"), 0)

        # More than 2 remaining dots -> -1
        # a.b.sub.example.com -> 4 dots -> -1
        self.assertEqual(extract_having_sub_domain("http://a.b.sub.example.com"), -1)
        # a.sub.example.com -> 3 dots -> -1
        self.assertEqual(extract_having_sub_domain("http://a.sub.example.com"), -1)

        # Validate against contract
        for res in [1, 0, -1]:
            self.assertIn(res, ALLOWED_VALUES["having_Sub_Domain"])

    def test_feature_8_https_token(self):
        # Normal https URL -> 1
        self.assertEqual(extract_https_token("https://paypal.com/login"), 1)
        # Normal http URL -> 1
        self.assertEqual(extract_https_token("http://paypal.com/login"), 1)
        # HTTP/HTTPS token inside domain -> -1 (case-insensitive)
        self.assertEqual(extract_https_token("http://https-www-paypal-example.com/login"), -1)
        self.assertEqual(extract_https_token("http://HTTP-paypal-fake.com/login"), -1)
        self.assertEqual(extract_https_token("http://login.paypal.https.evil.com/"), -1)

        # Validate against contract
        for res in [1, -1]:
            self.assertIn(res, ALLOWED_VALUES["HTTPS_token"])


if __name__ == "__main__":
    unittest.main()
