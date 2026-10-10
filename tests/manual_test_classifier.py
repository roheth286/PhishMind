"""
Manual Interactive Tester for URL Classification (predict_url).

Runs feature extraction and passes the 20-feature vector to the trained Random Forest model.
Outputs the predicted class label (1 = Legitimate, -1 = Phishing) and a clear disclaimer.

Does NOT guarantee safety; this is an automated ML model classification based on extracted features.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.classifier import predict_url, LABEL_DESCRIPTIONS
from src.feature_contract import FEATURE_NAMES


def main():
    print("=" * 60)
    print("PHISHING DETECTION - MANUAL URL CLASSIFIER TESTER")
    print("=" * 60)
    print("Disclaimer: Predictions are machine-learning classifications based on")
    print("extracted 20-feature vectors and do not guarantee safety.\n")

    while True:
        try:
            url = input("Enter a URL to classify: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url:
            print("URL cannot be empty. Please enter a valid URL.")
            continue

        print(f"\nAnalyzing and classifying: {url} ...")
        try:
            label, vector = predict_url(url)
        except Exception as e:
            print(f"Error during classification: {e}")
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

        description = LABEL_DESCRIPTIONS.get(label, "Unknown")

        print("\n" + "=" * 60)
        print("CLASSIFICATION RESULT")
        print("=" * 60)
        print(f"URL: {url}")
        print(f"Predicted Class Label: {label}")
        print(f"Classification:        {description.upper()}")
        print("-" * 60)
        print(f"Extracted 20-Feature Vector:")
        print(vector)
        print("=" * 60)
        print("Note: This classification is produced by the trained Random Forest")
        print("model evaluated on the 20 authoritative phishing detection features.")
        print("=" * 60)

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
