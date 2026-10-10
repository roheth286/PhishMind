"""
Tests for Section 2 Features (HTTPS / Network-Level Features).
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import ALLOWED_VALUES
from src.feature_extractor import (
    decide_ssl_final_state,
    decide_port_status,
    decide_redirect,
    extract_ssl_final_state,
    extract_port,
    extract_redirect,
    RESTRICTED_PORTS,
    PREFERRED_PORTS,
    TRUSTED_CA_LIST,
)


class TestSection2Features(unittest.TestCase):

    # --------------------------------------------------------------------------
    # SSLfinal_State Tests
    # --------------------------------------------------------------------------

    def test_ssl_final_state_non_https(self):
        """1. Non-HTTPS URL -> -1"""
        res = decide_ssl_final_state(is_https=False, issuer_str="GeoTrust Primary CA", cert_age_years=2.0)
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["SSLfinal_State"])

        # Also via extract_ssl_final_state with http scheme (deterministic, no network needed)
        self.assertEqual(extract_ssl_final_state("http://example.com"), -1)

    def test_ssl_final_state_https_trusted_ca_age_gte_1_year(self):
        """2. HTTPS + trusted issuer + certificate age >= 1 year -> 1"""
        for ca in TRUSTED_CA_LIST:
            issuer = f"CN={ca.title()} Inc, O={ca.title()}"
            res = decide_ssl_final_state(is_https=True, issuer_str=issuer, cert_age_years=1.0)
            self.assertEqual(res, 1, f"Failed for trusted CA: {ca}")
            self.assertIn(res, ALLOWED_VALUES["SSLfinal_State"])

            res_older = decide_ssl_final_state(is_https=True, issuer_str=issuer, cert_age_years=2.5)
            self.assertEqual(res_older, 1)

    def test_ssl_final_state_https_untrusted_ca(self):
        """3. HTTPS + untrusted issuer -> 0"""
        untrusted_issuers = [
            "CN=Let's Encrypt Authority X3",
            "CN=DigiCert Global Root CA",
            "CN=Cloudflare Inc ECC CA-3",
            "CN=Self-Signed Certificate",
        ]
        for issuer in untrusted_issuers:
            res = decide_ssl_final_state(is_https=True, issuer_str=issuer, cert_age_years=2.0)
            self.assertEqual(res, 0, f"Failed for untrusted CA: {issuer}")
            self.assertIn(res, ALLOWED_VALUES["SSLfinal_State"])

    def test_ssl_final_state_https_trusted_ca_age_lt_1_year(self):
        """4. HTTPS certificate younger than 1 year -> -1 ('otherwise' rule)"""
        res = decide_ssl_final_state(is_https=True, issuer_str="CN=GoDaddy Secure Certificate", cert_age_years=0.5)
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["SSLfinal_State"])

    # --------------------------------------------------------------------------
    # Port Tests
    # --------------------------------------------------------------------------

    def test_port_decision_preferred_open_restricted_closed(self):
        """Preferred ports open (80, 443) and all restricted ports closed -> 1"""
        port_states = {p: False for p in RESTRICTED_PORTS}
        port_states[80] = True
        port_states[443] = True
        res = decide_port_status(port_states)
        self.assertEqual(res, 1)
        self.assertIn(res, ALLOWED_VALUES["port"])

    def test_port_decision_only_one_preferred_open(self):
        """If port 80 is closed when preferred is open, decide_port_status returns -1"""
        port_states = {p: False for p in RESTRICTED_PORTS}
        port_states[80] = False
        port_states[443] = True
        self.assertEqual(decide_port_status(port_states), -1)

    def test_port_decision_restricted_ports_open(self):
        """Verify each of the 8 restricted ports being open results in -1"""
        for restricted_p in RESTRICTED_PORTS:
            port_states = {p: False for p in RESTRICTED_PORTS}
            port_states[80] = True
            port_states[443] = True
            # Open this restricted port
            port_states[restricted_p] = True
            res = decide_port_status(port_states)
            self.assertEqual(res, -1, f"Failed when restricted port {restricted_p} was open")
            self.assertIn(res, ALLOWED_VALUES["port"])

    def test_port_decision_preferred_ports_closed(self):
        """When preferred ports (80, 443) are closed -> -1"""
        port_states = {p: False for p in RESTRICTED_PORTS}
        port_states[80] = False
        port_states[443] = False
        self.assertEqual(decide_port_status(port_states), -1)

    # --------------------------------------------------------------------------
    # Redirect Tests
    # --------------------------------------------------------------------------

    def test_redirect_decision_mapping(self):
        """
        0 redirects -> 1
        1 redirect  -> 1
        2 redirects -> 0
        3 redirects -> 0
        4 redirects -> -1
        5 redirects -> -1
        """
        self.assertEqual(decide_redirect(0), 1)
        self.assertEqual(decide_redirect(1), 1)
        self.assertEqual(decide_redirect(2), 0)
        self.assertEqual(decide_redirect(3), 0)
        self.assertEqual(decide_redirect(4), -1)
        self.assertEqual(decide_redirect(5), -1)
        self.assertEqual(decide_redirect(10), -1)

        # Validate against contract
        for val in [0, 1]:
            self.assertIn(decide_redirect(val), ALLOWED_VALUES["Redirect"])
        for val in [2, 3]:
            self.assertIn(decide_redirect(val), ALLOWED_VALUES["Redirect"])
        for val in [4, 5]:
            self.assertIn(decide_redirect(val), ALLOWED_VALUES["Redirect"])


if __name__ == "__main__":
    unittest.main()
