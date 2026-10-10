"""
Manual Interactive Tester for Section 3 Features (HTML / Page-Content Features).

Tests:
11. Favicon
12. Request_URL
13. URL_of_Anchor
14. Links_in_tags
15. SFH
17. Iframe

Fetches the webpage HTML using fetch_webpage, gets the final URL after redirects,
extracts all 6 Section 3 features, prints the values, and displays the ordered vector:
[favicon, request_url, url_of_anchor, links_in_tags, sfh, iframe]
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_extractor import (
    fetch_webpage,
    extract_favicon,
    extract_request_url,
    extract_url_of_anchor,
    extract_links_in_tags,
    extract_sfh,
    extract_iframe,
)


def main():
    while True:
        try:
            url = input("Enter URL: ").strip()
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
                    print("Please enter y or n.")
            continue

        print("\n==================================================")
        print("SECTION 3 FEATURE EXTRACTION")
        print("==================================================")
        print(f"\nURL:\n{url}\n")
        print(f"Final URL:\n{final_url}\n")

        # 11. Favicon
        try:
            v_favicon = extract_favicon(html, final_url)
            print(f"11. Favicon\n   Value: {v_favicon}\n")
        except Exception as e:
            v_favicon = None
            print(f"11. Favicon\n   Error: {e}\n")

        # 12. Request_URL
        try:
            v_request_url = extract_request_url(html, final_url)
            print(f"12. Request_URL\n   Value: {v_request_url}\n")
        except Exception as e:
            v_request_url = None
            print(f"12. Request_URL\n   Error: {e}\n")

        # 13. URL_of_Anchor
        try:
            v_anchor = extract_url_of_anchor(html, final_url)
            print(f"13. URL_of_Anchor\n   Value: {v_anchor}\n")
        except Exception as e:
            v_anchor = None
            print(f"13. URL_of_Anchor\n   Error: {e}\n")

        # 14. Links_in_tags
        try:
            v_links_in_tags = extract_links_in_tags(html, final_url)
            print(f"14. Links_in_tags\n   Value: {v_links_in_tags}\n")
        except Exception as e:
            v_links_in_tags = None
            print(f"14. Links_in_tags\n   Error: {e}\n")

        # 15. SFH
        try:
            v_sfh = extract_sfh(html, final_url)
            print(f"15. SFH\n   Value: {v_sfh}\n")
        except Exception as e:
            v_sfh = None
            print(f"15. SFH\n   Error: {e}\n")

        # 17. Iframe
        try:
            v_iframe = extract_iframe(html)
            print(f"17. Iframe\n   Value: {v_iframe}\n")
        except Exception as e:
            v_iframe = None
            print(f"17. Iframe\n   Error: {e}\n")

        print("==================================================")
        section3_vector = [
            v_favicon,
            v_request_url,
            v_anchor,
            v_links_in_tags,
            v_sfh,
            v_iframe,
        ]
        print("\nSection 3 vector:")
        print(section3_vector)
        print("\n==================================================")

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
                print("Please enter y or n.")


if __name__ == "__main__":
    main()
