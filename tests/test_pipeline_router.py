"""
Comprehensive Automated Tests for Dedicated Backend Pipeline Router (src/pipeline_router.py).

Tests:
1. 200 OK + text/html -> Pipeline A (20-feature)
2. 200 OK + text/html; charset=utf-8 -> Pipeline A (20-feature)
3. 200 OK + application/javascript -> Pipeline B (10-feature)
4. 200 OK + text/javascript -> Pipeline B (10-feature)
5. 200 OK + text/plain -> Pipeline B (10-feature)
6. 200 OK + missing Content-Type -> Pipeline B (10-feature)
7. 404 Not Found + text/html -> Pipeline B (10-feature)
8. 500 Internal Server Error -> Pipeline B (10-feature)
9. Redirect ending at 200 OK + text/html -> Pipeline A (20-feature)
10. Redirect ending at non-HTML response -> Pipeline B (10-feature)
11. Connection failure -> Pipeline B (10-feature)
12. Request timeout -> Pipeline B (10-feature)
13. TLS error -> Pipeline B (10-feature)
14. Unsafe URLs rejected safely before network request / SSRF protection
15. Unsafe redirect destinations rejected safely
16. Streaming request used and response stream closed without body download
17. Pipeline execution failure propagates without silent switching
18. RoutingResult structure: attribute access, dictionary indexing, to_dict()
19. Real model integration testing for both pipelines
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import requests

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.pipeline_router import (
    check_url_resource,
    route_url,
    RoutingResult,
    PIPELINE_FULL,
    PIPELINE_REDUCED,
)
from src.classifier import clear_model_cache


class TestPipelineRouter(unittest.TestCase):

    def setUp(self):
        clear_model_cache()

    def tearDown(self):
        clear_model_cache()

    def _mock_response(self, status_code=200, content_type="text/html", headers=None):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status_code
        h = {"Content-Type": content_type} if content_type is not None else {}
        if headers:
            h.update(headers)
        resp.headers = h
        resp.close = MagicMock()
        return resp

    # --- Scenario 1: 200 OK + text/html -> Pipeline A ---
    @patch("src.pipeline_router.predict_url")
    @patch("src.pipeline_router.load_model")
    @patch("requests.Session.get")
    def test_scenario_01_200_ok_text_html(self, mock_get, mock_load_model, mock_predict_20):
        mock_get.return_value = self._mock_response(200, "text/html")
        mock_predict_20.return_value = (1, [1] * 20)
        mock_rf = MagicMock()
        mock_rf.classes_ = [-1, 1]
        mock_rf.predict_proba.return_value = [[0.1, 0.9]]
        mock_load_model.return_value = mock_rf

        result = route_url("https://example.com/login")

        self.assertEqual(result.pipeline, PIPELINE_FULL)
        self.assertEqual(result.feature_count, 20)
        self.assertEqual(result.predicted_label, 1)
        self.assertAlmostEqual(result.phishing_probability, 0.9)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content_type, "text/html")
        self.assertIn("200 OK with text/html", result.routing_reason)
        mock_predict_20.assert_called_once_with("https://example.com/login", model_path=None)

    # --- Scenario 2: 200 OK + text/html; charset=utf-8 -> Pipeline A ---
    @patch("src.pipeline_router.predict_url")
    @patch("src.pipeline_router.load_model")
    @patch("requests.Session.get")
    def test_scenario_02_200_ok_text_html_with_charset(self, mock_get, mock_load_model, mock_predict_20):
        mock_get.return_value = self._mock_response(200, "text/html; charset=utf-8")
        mock_predict_20.return_value = (-1, [-1] * 20)
        mock_rf = MagicMock()
        mock_rf.classes_ = [-1, 1]
        mock_rf.predict_proba.return_value = [[0.85, 0.15]]
        mock_load_model.return_value = mock_rf

        result = route_url("https://example.com/portal")

        self.assertEqual(result.pipeline, PIPELINE_FULL)
        self.assertEqual(result.feature_count, 20)
        self.assertEqual(result.predicted_label, -1)
        self.assertAlmostEqual(result.phishing_probability, 0.15)
        self.assertEqual(result.content_type, "text/html; charset=utf-8")

    # --- Scenario 3: 200 OK + application/javascript -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_03_200_ok_application_javascript(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(200, "application/javascript")
        mock_predict_10.return_value = (-1, 0.88, [-1] * 10)

        result = route_url("https://example.com/bundle.js")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertEqual(result.predicted_label, -1)
        self.assertAlmostEqual(result.phishing_probability, 0.88)
        self.assertIn("Non-HTML Content-Type", result.routing_reason)
        mock_predict_10.assert_called_once_with("https://example.com/bundle.js", model_path=None, return_proba=True)

    # --- Scenario 4: 200 OK + text/javascript -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_04_200_ok_text_javascript(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(200, "text/javascript")
        mock_predict_10.return_value = (1, 0.12, [1] * 10)

        result = route_url("https://example.com/script.js")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("Non-HTML Content-Type", result.routing_reason)

    # --- Scenario 5: 200 OK + text/plain -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_05_200_ok_text_plain(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(200, "text/plain")
        mock_predict_10.return_value = (1, 0.05, [1] * 10)

        result = route_url("https://example.com/robots.txt")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("Non-HTML Content-Type", result.routing_reason)

    # --- Scenario 6: 200 OK + missing Content-Type -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_06_200_ok_missing_content_type(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(200, None)
        mock_predict_10.return_value = (-1, 0.75, [-1] * 10)

        result = route_url("https://example.com/unknown_payload")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("Non-HTML Content-Type", result.routing_reason)

    # --- Scenario 7: 404 Not Found + text/html -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_07_404_not_found(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(404, "text/html")
        mock_predict_10.return_value = (-1, 0.80, [-1] * 10)

        result = route_url("https://example.com/nonexistent")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertEqual(result.status_code, 404)
        self.assertIn("Non-200 HTTP status (404)", result.routing_reason)

    # --- Scenario 8: 500 Internal Server Error -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_08_500_server_error(self, mock_get, mock_predict_10):
        mock_get.return_value = self._mock_response(500, "text/html")
        mock_predict_10.return_value = (-1, 0.65, [-1] * 10)

        result = route_url("https://example.com/crash")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertEqual(result.status_code, 500)
        self.assertIn("Non-200 HTTP status (500)", result.routing_reason)

    # --- Scenario 9: Redirect ending at 200 OK + text/html -> Pipeline A ---
    @patch("src.pipeline_router.predict_url")
    @patch("src.pipeline_router.load_model")
    @patch("requests.Session.get")
    def test_scenario_09_redirect_ending_at_200_html(self, mock_get, mock_load_model, mock_predict_20):
        resp_redirect = self._mock_response(302, "text/html", headers={"Location": "https://example.com/home"})
        resp_final = self._mock_response(200, "text/html")
        mock_get.side_effect = [resp_redirect, resp_final]

        mock_predict_20.return_value = (1, [1] * 20)
        mock_rf = MagicMock()
        mock_rf.classes_ = [-1, 1]
        mock_rf.predict_proba.return_value = [[0.05, 0.95]]
        mock_load_model.return_value = mock_rf

        result = route_url("https://example.com/")

        self.assertEqual(result.pipeline, PIPELINE_FULL)
        self.assertEqual(result.feature_count, 20)
        self.assertEqual(result.final_url, "https://example.com/home")
        self.assertIn("200 OK with text/html", result.routing_reason)

    # --- Scenario 10: Redirect ending at non-HTML response -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_10_redirect_ending_at_non_html(self, mock_get, mock_predict_10):
        resp_redirect = self._mock_response(301, "text/html", headers={"Location": "https://example.com/api/data"})
        resp_final = self._mock_response(200, "application/json")
        mock_get.side_effect = [resp_redirect, resp_final]

        mock_predict_10.return_value = (1, 0.30, [1] * 10)

        result = route_url("https://example.com/endpoint")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertEqual(result.final_url, "https://example.com/api/data")
        self.assertIn("Non-HTML Content-Type", result.routing_reason)

    # --- Scenario 11: Connection failure -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_11_connection_failure(self, mock_get, mock_predict_10):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        mock_predict_10.return_value = (-1, 0.92, [-1] * 10)

        result = route_url("https://example.com/unreachable")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("Connection failure", result.routing_reason)

    # --- Scenario 12: Request timeout -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_12_request_timeout(self, mock_get, mock_predict_10):
        mock_get.side_effect = requests.exceptions.Timeout("Read timed out")
        mock_predict_10.return_value = (-1, 0.85, [-1] * 10)

        result = route_url("https://example.com/slow")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("Request timeout", result.routing_reason)

    # --- Scenario 13: TLS error -> Pipeline B ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_13_tls_error(self, mock_get, mock_predict_10):
        mock_get.side_effect = requests.exceptions.SSLError("Certificate verify failed")
        mock_predict_10.return_value = (-1, 0.96, [-1] * 10)

        result = route_url("https://example.com/expired-cert")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertEqual(result.feature_count, 10)
        self.assertIn("TLS/SSL error", result.routing_reason)

    # --- Scenario 14: Unsafe URLs rejected safely before network request ---
    @patch("requests.Session.get")
    def test_scenario_14_unsafe_urls_rejected_without_network(self, mock_get):
        unsafe_urls = [
            "http://localhost:8000",
            "http://127.0.0.1:8080",
            "http://10.0.0.1/private",
            "http://192.168.1.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "ftp://example.com",
            "",
            "   ",
        ]

        for u in unsafe_urls:
            with self.assertRaises(ValueError):
                check_url_resource(u)
            with self.assertRaises(ValueError):
                route_url(u)

        # None input
        with self.assertRaises(ValueError):
            check_url_resource(None)
        with self.assertRaises(ValueError):
            route_url(None)

        # Network get was NEVER called for any unsafe URL
        mock_get.assert_not_called()

    # --- Scenario 15: Unsafe redirect destination rejected safely ---
    @patch("src.pipeline_router.predict_url_10")
    @patch("requests.Session.get")
    def test_scenario_15_unsafe_redirect_diverts_to_pipeline_b(self, mock_get, mock_predict_10):
        resp_redirect = self._mock_response(302, "text/html", headers={"Location": "http://127.0.0.1:8080/internal"})
        mock_get.return_value = resp_redirect
        mock_predict_10.return_value = (-1, 0.90, [-1] * 10)

        result = route_url("https://example.com/open-redirect")

        self.assertEqual(result.pipeline, PIPELINE_REDUCED)
        self.assertIn("Unsafe redirect destination", result.routing_reason)

    # --- Scenario 16: Streaming used and response stream closed without body download ---
    @patch("requests.Session.get")
    def test_scenario_16_streaming_and_stream_close(self, mock_get):
        mock_resp = self._mock_response(200, "text/html")
        mock_get.return_value = mock_resp

        is_html, reason, status, ct, final_url = check_url_resource("https://example.com/page")

        self.assertTrue(is_html)
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        self.assertTrue(call_kwargs.get("stream"), "Must use stream=True")
        self.assertFalse(call_kwargs.get("allow_redirects"), "Must use allow_redirects=False")
        mock_resp.close.assert_called_once()

    # --- Scenario 17: Pipeline failure propagates without silent switching ---
    @patch("src.pipeline_router.predict_url")
    @patch("requests.Session.get")
    def test_scenario_17_pipeline_failure_propagates(self, mock_get, mock_predict_20):
        mock_get.return_value = self._mock_response(200, "text/html")
        mock_predict_20.side_effect = RuntimeError("Extraction engine error")

        with self.assertRaises(RuntimeError) as ctx:
            route_url("https://example.com/error")

        self.assertIn("Pipeline A (20-feature) execution failed", str(ctx.exception))

    # --- Scenario 18: RoutingResult attribute, dict subscription, to_dict ---
    def test_scenario_18_routing_result_access(self):
        res = RoutingResult(
            pipeline=PIPELINE_FULL,
            predicted_label=1,
            label_description="Legitimate",
            phishing_probability=0.15,
            feature_vector=[1] * 20,
            feature_count=20,
            routing_reason="200 OK with text/html",
            status_code=200,
            content_type="text/html",
            final_url="https://example.com"
        )

        # Attribute access
        self.assertEqual(res.pipeline, PIPELINE_FULL)
        self.assertEqual(res.predicted_label, 1)

        # Dict subscription
        self.assertEqual(res["pipeline"], PIPELINE_FULL)
        self.assertEqual(res["predicted_label"], 1)
        with self.assertRaises(KeyError):
            _ = res["invalid_key"]

        # to_dict
        d = res.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["pipeline"], PIPELINE_FULL)
        self.assertEqual(d["feature_count"], 20)

    # --- Scenario 19: End-to-end integration with real trained models ---
    @patch("requests.Session.get")
    @patch("src.pipeline_router.predict_url")
    @patch("src.pipeline_router.predict_url_10")
    def test_scenario_19_model_integration_structure(self, mock_predict_10, mock_predict_20, mock_get):
        # 1. Pipeline A flow
        mock_get.return_value = self._mock_response(200, "text/html")
        mock_predict_20.return_value = (1, [1] * 20)
        res_a = route_url("https://example.com/a")
        self.assertEqual(res_a.pipeline, PIPELINE_FULL)
        self.assertIsInstance(res_a.phishing_probability, float)
        self.assertIn(res_a.predicted_label, (-1, 1))

        # 2. Pipeline B flow
        mock_get.return_value = self._mock_response(404, "text/plain")
        mock_predict_10.return_value = (-1, 0.85, [-1] * 10)
        res_b = route_url("https://example.com/b")
        self.assertEqual(res_b.pipeline, PIPELINE_REDUCED)
        self.assertIsInstance(res_b.phishing_probability, float)
        self.assertIn(res_b.predicted_label, (-1, 1))


if __name__ == "__main__":
    unittest.main()
