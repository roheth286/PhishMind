"""
Manual Interactive Tester for Pipeline Router (route_url).

Tests the backend routing logic:
- Performs resource-check on submitted URL (status code, Content-Type).
- Selects Pipeline A (20-feature) or Pipeline B (10-feature).
- Executes inference and prints routing decisions, probabilities, and feature vectors.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.pipeline_router import route_url, PIPELINE_FULL, PIPELINE_REDUCED


def main():
    print("=" * 65)
    print("PHISHING DETECTION - MANUAL BACKEND PIPELINE ROUTER TESTER")
    print("=" * 65)
    print("Routing Rule:")
    print(" - Pipeline A (20-feature): HTTP 200 OK with Content-Type text/html")
    print(" - Pipeline B (10-feature): Non-200, non-HTML, timeouts, TLS errors, etc.")
    print("=" * 65 + "\n")

    while True:
        try:
            url = input("Enter a URL to test router: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url:
            print("URL cannot be empty. Please enter a valid URL.")
            continue

        print(f"\nEvaluating routing and running inference for: {url} ...")
        try:
            result = route_url(url)
        except Exception as e:
            print(f"\n[ERROR] Pipeline routing/execution failed: {e}")
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

        pipeline_label = "PIPELINE A (Full 20-Feature Model)" if result.pipeline == PIPELINE_FULL else "PIPELINE B (Reduced 10-Feature Model)"

        print("\n" + "=" * 65)
        print("ROUTING DECISION & INFERENCE RESULT")
        print("=" * 65)
        print(f"Submitted URL:         {url}")
        print(f"Final URL:             {result.final_url or url}")
        print(f"HTTP Status Code:      {result.status_code}")
        print(f"Content-Type:          {result.content_type or 'None'}")
        print(f"Routing Decision:      {pipeline_label}")
        print(f"Routing Reason:        {result.routing_reason}")
        print("-" * 65)
        print(f"Predicted Class Label: {result.predicted_label}")
        print(f"Classification:        {result.label_description.upper()}")
        print(f"Phishing Probability:  {result.phishing_probability:.4f} ({result.phishing_probability * 100:.1f}%)")
        print(f"Feature Vector Count:  {result.feature_count} features")
        print(f"Feature Vector:        {result.feature_vector}")
        print("=" * 65)

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
