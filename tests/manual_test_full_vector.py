"""
Manual Interactive Tester for the Complete 20-Feature Vector Extractor.

This script calls extract_features(url), displays all 20 extracted features
grouped by section with their authoritative positions, prints the assembled
20-value vector in exact 1–20 order, and validates it against the feature contract.

Does NOT call the Random Forest model or perform phishing prediction.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_contract import validate_feature_vector, FEATURE_NAMES
from src.feature_extractor import extract_features


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

        print(f"\nExtracting full 20-feature vector for: {url} ...")
        try:
            vector = extract_features(url)
        except Exception as e:
            print(f"Error during feature extraction: {e}")
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

        # Map vector to names and 1-based positions
        # vector index 0 is position 1, index 19 is position 20
        feature_map = {i + 1: (FEATURE_NAMES[i], vector[i]) for i in range(len(vector))}

        print("\n==================================================")
        print("FULL 20-FEATURE VECTOR EXTRACTION")
        print("==================================================")
        print(f"\nURL:\n{url}\n")

        print("SECTION 1 (URL String / Structure)")
        for pos in (1, 2, 3, 4, 5, 6, 7, 10):
            name, val = feature_map[pos]
            print(f"{pos}. {name}: {val}")

        print("\nSECTION 2 (HTTPS / Network-Level)")
        for pos in (8, 9, 18):
            name, val = feature_map[pos]
            print(f"{pos}. {name}: {val}")

        print("\nSECTION 3 (HTML / Page-Content)")
        for pos in (11, 12, 13, 14, 15, 17):
            name, val = feature_map[pos]
            print(f"{pos}. {name}: {val}")

        print("\nSECTION 4 (JavaScript / Event / Submission)")
        for pos in (16, 19, 20):
            name, val = feature_map[pos]
            print(f"{pos}. {name}: {val}")

        print("\n==================================================")
        print("Final 20-feature vector (Positions 1 to 20):")
        print(vector)
        print("==================================================")

        # Confirm validation status
        try:
            is_valid = validate_feature_vector(vector)
            if is_valid:
                print("Vector validation:")
                print("PASSED (all 20 features conform to contract specification)")
        except Exception as e:
            print("Vector validation:")
            print(f"FAILED: {e}")
        print("==================================================")

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
