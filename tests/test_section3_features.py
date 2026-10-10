"""
Tests for Section 3 Features (HTML / Page-Content Features).
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import ALLOWED_VALUES
from src.feature_extractor import (
    extract_favicon,
    extract_request_url,
    extract_url_of_anchor,
    extract_links_in_tags,
    extract_sfh,
    extract_iframe,
)


class TestSection3Features(unittest.TestCase):

    # --------------------------------------------------------------------------
    # Favicon Tests
    # --------------------------------------------------------------------------

    def test_favicon_no_favicon(self):
        """1. No favicon -> 1"""
        html = "<html><head><title>Test</title></head><body></body></html>"
        res = extract_favicon(html, "https://example.com/page")
        self.assertEqual(res, 1)
        self.assertIn(res, ALLOWED_VALUES["Favicon"])

    def test_favicon_same_domain(self):
        """2. Same-domain favicon -> 1"""
        html = '<html><head><link rel="icon" href="https://example.com/favicon.ico"></head></html>'
        res = extract_favicon(html, "https://example.com/page")
        self.assertEqual(res, 1)

    def test_favicon_external_domain(self):
        """3. External-domain favicon -> -1"""
        html = '<html><head><link rel="icon" href="https://malicious.net/icon.ico"></head></html>'
        res = extract_favicon(html, "https://example.com/page")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["Favicon"])

    def test_favicon_relative_url(self):
        """4. Relative favicon URL -> correctly resolved against page_url -> 1"""
        html = '<html><head><link rel="shortcut icon" href="/static/favicon.png"></head></html>'
        res = extract_favicon(html, "https://example.com/sub/index.html")
        self.assertEqual(res, 1)

    # --------------------------------------------------------------------------
    # Request_URL Tests
    # --------------------------------------------------------------------------

    def test_request_url_zero_objects(self):
        """No embedded objects -> 1"""
        html = "<html><body><p>Hello world</p></body></html>"
        res = extract_request_url(html, "https://example.com")
        self.assertEqual(res, 1)
        self.assertIn(res, ALLOWED_VALUES["Request_URL"])

    def test_request_url_thresholds(self):
        """
        percentage < 22 -> 1
        22 <= percentage <= 61 -> 0
        percentage > 61 -> -1
        """
        # 100 objects: 0 external (0%) -> 1
        html_0 = "".join([f'<img src="/img{i}.png">' for i in range(100)])
        self.assertEqual(extract_request_url(html_0, "https://example.com"), 1)

        # 100 objects: 21 external (21%) -> 1
        html_21 = "".join([f'<img src="https://cdn.other.com/{i}.png">' for i in range(21)]) + \
                  "".join([f'<img src="/img{i}.png">' for i in range(79)])
        self.assertEqual(extract_request_url(html_21, "https://example.com"), 1)

        # 100 objects: 22 external (22%) -> 0
        html_22 = "".join([f'<img src="https://cdn.other.com/{i}.png">' for i in range(22)]) + \
                  "".join([f'<img src="/img{i}.png">' for i in range(78)])
        self.assertEqual(extract_request_url(html_22, "https://example.com"), 0)

        # 100 objects: 61 external (61%) -> 0
        html_61 = "".join([f'<img src="https://cdn.other.com/{i}.png">' for i in range(61)]) + \
                  "".join([f'<img src="/img{i}.png">' for i in range(39)])
        self.assertEqual(extract_request_url(html_61, "https://example.com"), 0)

        # 100 objects: 62 external (62%) -> -1
        html_62 = "".join([f'<img src="https://cdn.other.com/{i}.png">' for i in range(62)]) + \
                  "".join([f'<img src="/img{i}.png">' for i in range(38)])
        self.assertEqual(extract_request_url(html_62, "https://example.com"), -1)

        # 100% external -> -1
        html_100 = "".join([f'<img src="https://cdn.other.com/{i}.png">' for i in range(10)])
        self.assertEqual(extract_request_url(html_100, "https://example.com"), -1)

    # --------------------------------------------------------------------------
    # URL_of_Anchor Tests
    # --------------------------------------------------------------------------

    def test_url_of_anchor_zero_anchors(self):
        """No anchors -> 1"""
        html = "<html><body><p>No links</p></body></html>"
        self.assertEqual(extract_url_of_anchor(html, "https://example.com"), 1)

    def test_url_of_anchor_suspicious_types(self):
        """Test #, #content, #skip, javascript:void(0), and external domains count as suspicious"""
        page_url = "https://example.com"
        html = """
        <a href="#">Link 1</a>
        <a href="#content">Link 2</a>
        <a href="#skip">Link 3</a>
        <a href="javascript:void(0)">Link 4</a>
        <a href="https://phishing.net/login">Link 5</a>
        """
        # All 5 are suspicious -> 100% -> -1
        res = extract_url_of_anchor(html, page_url)
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["URL_of_Anchor"])

    def test_url_of_anchor_thresholds(self):
        """
        percentage < 31 -> 1
        31 <= percentage <= 67 -> 0
        percentage > 67 -> -1
        """
        page_url = "https://example.com"
        # 100 anchors: 0 suspicious -> 1
        html_0 = "".join([f'<a href="/local_{i}">L</a>' for i in range(100)])
        self.assertEqual(extract_url_of_anchor(html_0, page_url), 1)

        # 100 anchors: 30 suspicious (30%) -> 1
        html_30 = "".join(['<a href="#">S</a>' for _ in range(30)]) + \
                  "".join([f'<a href="/local_{i}">L</a>' for i in range(70)])
        self.assertEqual(extract_url_of_anchor(html_30, page_url), 1)

        # 100 anchors: 31 suspicious (31%) -> 0
        html_31 = "".join(['<a href="#">S</a>' for _ in range(31)]) + \
                  "".join([f'<a href="/local_{i}">L</a>' for i in range(69)])
        self.assertEqual(extract_url_of_anchor(html_31, page_url), 0)

        # 100 anchors: 67 suspicious (67%) -> 0
        html_67 = "".join(['<a href="#">S</a>' for _ in range(67)]) + \
                  "".join([f'<a href="/local_{i}">L</a>' for i in range(33)])
        self.assertEqual(extract_url_of_anchor(html_67, page_url), 0)

        # 100 anchors: 68 suspicious (68%) -> -1
        html_68 = "".join(['<a href="#">S</a>' for _ in range(68)]) + \
                  "".join([f'<a href="/local_{i}">L</a>' for i in range(32)])
        self.assertEqual(extract_url_of_anchor(html_68, page_url), -1)

    def test_url_of_anchor_iana_fixture(self):
        """Regression test: HTML fixture containing external iana.org anchor returns -1 for example.com"""
        fixture_html = (
            '<!doctype html><html><head><title>Example Domain</title></head><body>'
            '<p>This domain is for use in documentation examples.</p>'
            '<a href="https://iana.org/help/example-domains">Learn more</a>'
            '</body></html>'
        )
        # 1 anchor, 100% external (iana.org vs example.com) -> percentage = 100% > 67% -> -1
        res = extract_url_of_anchor(fixture_html, "https://example.com/")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["URL_of_Anchor"])

    # --------------------------------------------------------------------------
    # Links_in_tags Tests
    # --------------------------------------------------------------------------

    def test_links_in_tags_zero_tags(self):
        """No relevant tags -> 1"""
        html = "<html><body><p>Clean</p></body></html>"
        self.assertEqual(extract_links_in_tags(html, "https://example.com"), 1)

    def test_links_in_tags_thresholds(self):
        """
        percentage < 17 -> 1
        17 <= percentage <= 81 -> 0
        percentage > 81 -> -1
        """
        page_url = "https://example.com"

        # 100 tag links: 0 external (0%) -> 1
        html_0 = "".join([f'<link href="/style{i}.css">' for i in range(100)])
        self.assertEqual(extract_links_in_tags(html_0, page_url), 1)

        # 100 tag links: 16 external (16%) -> 1
        html_16 = "".join([f'<script src="https://cdn.ext.com/{i}.js"></script>' for i in range(16)]) + \
                  "".join([f'<link href="/style{i}.css">' for i in range(84)])
        self.assertEqual(extract_links_in_tags(html_16, page_url), 1)

        # 100 tag links: 17 external (17%) -> 0
        html_17 = "".join([f'<script src="https://cdn.ext.com/{i}.js"></script>' for i in range(17)]) + \
                  "".join([f'<link href="/style{i}.css">' for i in range(83)])
        self.assertEqual(extract_links_in_tags(html_17, page_url), 0)

        # 100 tag links: 81 external (81%) -> 0
        html_81 = "".join([f'<script src="https://cdn.ext.com/{i}.js"></script>' for i in range(81)]) + \
                  "".join([f'<link href="/style{i}.css">' for i in range(19)])
        self.assertEqual(extract_links_in_tags(html_81, page_url), 0)

        # 100 tag links: 82 external (82%) -> -1
        html_82 = "".join([f'<script src="https://cdn.ext.com/{i}.js"></script>' for i in range(82)]) + \
                  "".join([f'<link href="/style{i}.css">' for i in range(18)])
        self.assertEqual(extract_links_in_tags(html_82, page_url), -1)

    # --------------------------------------------------------------------------
    # SFH Tests
    # --------------------------------------------------------------------------

    def test_sfh_about_blank(self):
        """<form action="about:blank"> -> -1"""
        html = '<form action="about:blank"><input type="submit"></form>'
        res = extract_sfh(html, "https://example.com")
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["SFH"])

    def test_sfh_empty_action(self):
        """<form action=""> -> -1"""
        html = '<form action=""><input type="submit"></form>'
        self.assertEqual(extract_sfh(html, "https://example.com"), -1)
        # missing action -> -1
        html_no_action = '<form><input type="submit"></form>'
        self.assertEqual(extract_sfh(html_no_action, "https://example.com"), -1)

    def test_sfh_same_domain(self):
        """Same-domain action -> 1"""
        html = '<form action="https://example.com/login.php"><input></form>'
        self.assertEqual(extract_sfh(html, "https://example.com"), 1)
        # relative same domain action
        html_rel = '<form action="/submit"><input></form>'
        self.assertEqual(extract_sfh(html_rel, "https://example.com"), 1)

    def test_sfh_external_domain(self):
        """External-domain action -> 0"""
        html = '<form action="https://external-auth.com/login"><input></form>'
        res = extract_sfh(html, "https://example.com")
        self.assertEqual(res, 0)
        self.assertIn(res, ALLOWED_VALUES["SFH"])

    # --------------------------------------------------------------------------
    # Iframe Tests
    # --------------------------------------------------------------------------

    def test_iframe_no_iframe(self):
        """No iframe -> 1"""
        html = "<html><body><div>No iframe here</div></body></html>"
        res = extract_iframe(html)
        self.assertEqual(res, 1)
        self.assertIn(res, ALLOWED_VALUES["Iframe"])

    def test_iframe_present(self):
        """Any iframe (visible or invisible) -> -1"""
        html_vis = '<html><body><iframe src="https://example.com"></iframe></body></html>'
        self.assertEqual(extract_iframe(html_vis), -1)

        html_invis = '<html><body><iframe src="https://evil.com" style="display:none;width:0;height:0;"></iframe></body></html>'
        res = extract_iframe(html_invis)
        self.assertEqual(res, -1)
        self.assertIn(res, ALLOWED_VALUES["Iframe"])


    # --------------------------------------------------------------------------
    # Fetch Webpage Tests (Rendered DOM & Static Fallback)
    # --------------------------------------------------------------------------

    def test_fetch_webpage_rendered_format(self):
        """Verify rendered-fetch path returns (html, final_url) using mocked Playwright."""
        from unittest.mock import MagicMock, patch
        import sys
        from src.feature_extractor import fetch_webpage

        mock_page = MagicMock()
        mock_page.content.return_value = "<html><body><h1>Rendered DOM</h1></body></html>"
        mock_page.url = "https://example.com/final"

        mock_browser = MagicMock()
        mock_browser.new_page.return_value = mock_page

        mock_p = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser

        mock_pw_cm = MagicMock()
        mock_pw_cm.__enter__.return_value = mock_p
        mock_pw_cm.__exit__.return_value = False

        mock_sync_api = MagicMock()
        mock_sync_api.sync_playwright.return_value = mock_pw_cm

        with patch.dict(sys.modules, {"playwright": MagicMock(), "playwright.sync_api": mock_sync_api}):
            html, final_url = fetch_webpage("https://example.com/")
            self.assertEqual(html, "<html><body><h1>Rendered DOM</h1></body></html>")
            self.assertEqual(final_url, "https://example.com/final")
            mock_browser.close.assert_called_once()

    def test_fetch_webpage_browser_closed_on_navigation_error(self):
        """Verify browser.close() is called in finally block even if navigation raises an exception."""
        from unittest.mock import MagicMock, patch
        import sys
        from src.feature_extractor import fetch_webpage

        mock_page = MagicMock()
        mock_page.goto.side_effect = Exception("Navigation timeout")

        mock_browser = MagicMock()
        mock_browser.new_page.return_value = mock_page

        mock_p = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser

        mock_pw_cm = MagicMock()
        mock_pw_cm.__enter__.return_value = mock_p
        mock_pw_cm.__exit__.return_value = False

        mock_sync_api = MagicMock()
        mock_sync_api.sync_playwright.return_value = mock_pw_cm

        with patch.dict(sys.modules, {"playwright": MagicMock(), "playwright.sync_api": mock_sync_api}):
            with patch("src.feature_extractor.fetch_webpage_static", return_value=("<html>static</html>", "https://example.com/")):
                html, final_url = fetch_webpage("https://example.com/")
                mock_browser.close.assert_called_once()
                self.assertEqual(html, "<html>static</html>")
                self.assertEqual(final_url, "https://example.com/")

    def test_fetch_webpage_fallback_to_static_when_playwright_unavailable(self):
        """Verify fetch_webpage falls back to static urllib when Playwright is not installed or raises."""
        from unittest.mock import patch
        import sys
        from src.feature_extractor import fetch_webpage

        with patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}):
            with patch("src.feature_extractor.fetch_webpage_static", return_value=("<html>fallback</html>", "https://example.com/")) as mock_static:
                html, final_url = fetch_webpage("https://example.com/")
                self.assertEqual(html, "<html>fallback</html>")
                self.assertEqual(final_url, "https://example.com/")
                mock_static.assert_called_once()


if __name__ == "__main__":
    unittest.main()
