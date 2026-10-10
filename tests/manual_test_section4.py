"""
Manual Interactive Tester for Section 4 Features:
- Submitting_to_email (Position 16)
- on_mouseover (Position 19)
- RightClick (Position 20)

Inspects:
- Inline HTML and JavaScript (event handlers, script tags)
- External JavaScript files referenced by <script src="..."> tags

Does NOT execute any JavaScript.
Does NOT perform phishing prediction or call the Random Forest model.
"""

import sys
import os
from typing import Optional
import requests

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_extractor import (
    fetch_webpage,
    collect_javascript_sources,
    extract_external_script_urls,
    extract_submitting_to_email,
    extract_on_mouseover,
    extract_right_click,
    MAX_EXTERNAL_SCRIPTS,
)


class CachedResponse:
    """Lightweight response object mimicking requests response for cached responses."""
    def __init__(self, status_code: int, headers: dict, content: bytes, encoding: Optional[str] = "utf-8"):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.encoding = encoding

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i : i + chunk_size]


class _WrappingResponse:
    """Wraps requests streaming response to cache content chunks in memory upon read."""
    def __init__(self, raw_resp, cache_dict, url):
        self._resp = raw_resp
        self._cache_dict = cache_dict
        self._url = url
        self.status_code = raw_resp.status_code
        self.headers = raw_resp.headers
        self.encoding = raw_resp.encoding
        self._chunks = []

    def iter_content(self, chunk_size=8192):
        try:
            for chunk in self._resp.iter_content(chunk_size=chunk_size):
                self._chunks.append(chunk)
                yield chunk
        finally:
            self._cache_dict[self._url] = (
                self.status_code,
                dict(self.headers),
                b"".join(self._chunks),
                self.encoding,
            )


class CachingSession(requests.Session):
    """
    Session that caches external script GET responses in memory to prevent
    redundant network fetches across multiple Section 4 feature functions.
    """
    def __init__(self):
        super().__init__()
        self._cache = {}

    def get(self, url, **kwargs):
        if url in self._cache:
            item = self._cache[url]
            if isinstance(item, Exception):
                raise item
            status, headers, content, encoding = item
            return CachedResponse(status, headers, content, encoding)

        try:
            resp = super().get(url, **kwargs)
        except Exception as e:
            self._cache[url] = e
            raise e

        # Redirect response: cache headers immediately
        if resp.status_code in (301, 302, 303, 307, 308):
            self._cache[url] = (resp.status_code, dict(resp.headers), b"", resp.encoding)
            return resp

        # 200 OK: wrap iter_content to cache chunks when consumed
        if resp.status_code == 200:
            return _WrappingResponse(resp, self._cache, url)

        # Non-200 responses
        self._cache[url] = (resp.status_code, dict(resp.headers), b"", resp.encoding)
        return resp


def main():
    while True:
        try:
            url = input("Enter a URL to analyze: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url:
            print("URL cannot be empty. Please enter a valid URL.")
            continue

        print(f"\nFetching webpage: {url} ...")
        try:
            html, final_url = fetch_webpage(url)
        except Exception as e:
            print(f"Error fetching webpage: {e}")
            while True:
                try:
                    choice = input("\nEnter another URL? (y/n): ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "n"

                if choice in ("y", "yes"):
                    print()
                    break
                elif choice in ("n", "no"):
                    print("Exiting.")
                    return
                else:
                    print("Please enter 'y' or 'n'.")
            continue

        # Create session with in-memory caching to avoid duplicate script downloads
        session = CachingSession()

        # Collect JavaScript sources once to inspect and pre-cache external scripts
        try:
            js_data = collect_javascript_sources(html, final_url, session=session)
        except Exception as e:
            js_data = {
                "inline_scripts": [],
                "event_handlers": [],
                "external_scripts": [],
            }
            print(f"Warning: Could not collect all JavaScript sources: {e}")

        print("\n==================================================")
        print("SECTION 4 FEATURE EXTRACTION")
        print("==================================================")
        print(f"\nURL:\n{url}\n")
        print(f"Final URL:\n{final_url}\n")

        # 16. Submitting_to_email
        try:
            v_email = extract_submitting_to_email(html, final_url, session=session)
            print(f"16. Submitting_to_email\n   Value: {v_email}\n")
        except Exception as e:
            v_email = None
            print(f"16. Submitting_to_email\n   Error: {e}\n")

        # 19. on_mouseover
        try:
            v_mouseover = extract_on_mouseover(html, final_url, session=session)
            print(f"19. on_mouseover\n   Value: {v_mouseover}\n")
        except Exception as e:
            v_mouseover = None
            print(f"19. on_mouseover\n   Error: {e}\n")

        # 20. RightClick
        try:
            v_rightclick = extract_right_click(html, final_url, session=session)
            print(f"20. RightClick\n   Value: {v_rightclick}\n")
        except Exception as e:
            v_rightclick = None
            print(f"20. RightClick\n   Error: {e}\n")

        print("==================================================")
        section4_vector = [
            v_email,
            v_mouseover,
            v_rightclick,
        ]
        print("\nSection 4 vector:")
        print(section4_vector)
        print("\n==================================================")

        # Source-inspection diagnostics
        inline_scripts = js_data.get("inline_scripts", [])
        event_handlers = js_data.get("event_handlers", [])
        external_scripts = js_data.get("external_scripts", [])
        total_inline = len(inline_scripts) + len(event_handlers)

        all_external_urls = extract_external_script_urls(html, final_url)
        candidate_count = min(len(all_external_urls), MAX_EXTERNAL_SCRIPTS)
        fetched_count = len(external_scripts)
        failed_count = max(0, candidate_count - fetched_count)

        print("--------------------------------------------------")
        print("SOURCE-INSPECTION DIAGNOSTICS:")
        print("--------------------------------------------------")
        print(f"- Inline JavaScript blocks: {len(inline_scripts)}")
        print(f"- Inline event handlers: {len(event_handlers)}")
        print(f"- Total inline sources inspected: {total_inline}")
        print(f"- External script URLs found on page: {len(all_external_urls)}")
        print(f"- External scripts considered (max {MAX_EXTERNAL_SCRIPTS}): {candidate_count}")
        print(f"- External scripts successfully fetched: {fetched_count}")
        print(f"- External scripts failed / inaccessible: {failed_count}")

        if failed_count > 0:
            print(f"\nWarning: {failed_count} external script(s) could not be fetched (network error, timeout, non-200 status, or blocked by SSRF/safety rules).")

        if len(all_external_urls) > MAX_EXTERNAL_SCRIPTS:
            print(f"\nNote: Page references {len(all_external_urls)} external scripts; only the first {MAX_EXTERNAL_SCRIPTS} were inspected per safety bounds.")
        print("--------------------------------------------------")

        # Loop prompt
        while True:
            try:
                choice = input("\nEnter another URL? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = "n"

            if choice in ("y", "yes"):
                print()
                break
            elif choice in ("n", "no"):
                print("Exiting.")
                return
            else:
                print("Please enter 'y' or 'n'.")


if __name__ == "__main__":
    main()
