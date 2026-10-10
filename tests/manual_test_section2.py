"""
Manual Interactive Tester for Section 2 Features (HTTPS / Network-Level Features).

Tests:
8. SSLfinal_State
9. port
18. Redirect

Displays individual feature values and the ordered 3-value vector:
[SSLfinal_State, port, Redirect]
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_extractor import (
    extract_ssl_final_state,
    extract_port,
    extract_redirect,
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

        print("\n==================================================")
        print("SECTION 2 FEATURE EXTRACTION")
        print("==================================================")
        print(f"\nURL:\n{url}\n")

        # 8. SSLfinal_State
        ssl_val = None
        try:
            ssl_val = extract_ssl_final_state(url)
            print(f"8. SSLfinal_State\n   Value: {ssl_val}\n")
        except Exception as e:
            print(f"8. SSLfinal_State\n   Error: {e}\n")

        # 9. port
        port_val = None
        try:
            port_val = extract_port(url)
            print(f"9. port\n   Value: {port_val}\n")
        except Exception as e:
            print(f"9. port\n   Error: {e}\n")

        # 18. Redirect
        redirect_val = None
        try:
            redirect_val = extract_redirect(url)
            print(f"18. Redirect\n   Value: {redirect_val}\n")
        except Exception as e:
            print(f"18. Redirect\n   Error: {e}\n")

        print("==================================================")
        section2_vector = [ssl_val, port_val, redirect_val]
        print("\nSection 2 vector:")
        print(section2_vector)
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
