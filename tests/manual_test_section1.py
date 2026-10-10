"""
Manual Interactive Tester for Section 1 Features (URL String / URL Structure).

Prompts the user for a URL, extracts all 8 Section 1 features, prints the values
and the ordered vector, and loops until the user chooses to exit.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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

        v1 = extract_having_ip_address(url)
        v2 = extract_url_length(url)
        v3 = extract_shortining_service(url)
        v4 = extract_having_at_symbol(url)
        v5 = extract_double_slash_redirecting(url)
        v6 = extract_prefix_suffix(url)
        v7 = extract_having_sub_domain(url)
        v8 = extract_https_token(url)

        vector = [v1, v2, v3, v4, v5, v6, v7, v8]

        print("\n==================================================")
        print("SECTION 1 FEATURE EXTRACTION")
        print("==================================================")
        print(f"\nURL:\n{url}\n")
        print(f"1. having_IP_Address\n   Value: {v1}\n")
        print(f"2. URL_Length\n   Value: {v2}\n")
        print(f"3. Shortining_Service\n   Value: {v3}\n")
        print(f"4. having_At_Symbol\n   Value: {v4}\n")
        print(f"5. double_slash_redirecting\n   Value: {v5}\n")
        print(f"6. Prefix_Suffix\n   Value: {v6}\n")
        print(f"7. having_Sub_Domain\n   Value: {v7}\n")
        print(f"8. HTTPS_token\n   Value: {v8}")
        print("==================================================")
        print("\nSection 1 vector:")
        print(vector)
        print()

        try:
            choice = input("Enter another URL? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice != "y":
            print("Exiting.")
            break


if __name__ == "__main__":
    main()
