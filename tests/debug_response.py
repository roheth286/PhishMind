import sys
import os

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from urllib.request import Request, build_opener

url = "https://example.com/"

req = Request(
    url,
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
)

with build_opener().open(req, timeout=10) as response:
    print("Status:", response.status)
    print("Requested URL:", url)
    print("Final URL:", response.geturl())
    print("Content-Type:", response.headers.get("Content-Type"))
    print("Content-Length:", response.headers.get("Content-Length"))
    print("Server:", response.headers.get("Server"))
    print("All response headers:")
    print(response.headers)

    body = response.read().decode(
        response.headers.get_content_charset() or "utf-8",
        errors="replace"
    )

    print("\nBody length:", len(body))
    print("Contains iana.org:", "iana.org" in body.lower())
    print("\nBody:")
    print(body)