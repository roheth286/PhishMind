import sys
import os

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from src.feature_extractor import fetch_webpage


URL = "https://example.com/"

html, final_url = fetch_webpage(URL)

print("=" * 70)
print("FINAL URL")
print("=" * 70)
print(final_url)

print("\n" + "=" * 70)
print("HTML LENGTH")
print("=" * 70)
print(len(html))

print("\n" + "=" * 70)
print("ACTUAL HTML RETURNED BY fetch_webpage()")
print("=" * 70)
print(html)

print("\n" + "=" * 70)
print("END")
print("=" * 70)