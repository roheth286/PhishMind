"""
Diagnostic Script for URL Safety Validation and DNS/IP Routing Failure.

Instruments and tests:
1. Environment verification (Python version, OS, interpreter, repeated DNS).
2. Step-by-step diagnostic trace of https://example.com/ across every branch of _is_safe_url_destination.
3. Isolated evaluation of _is_public_ip() and _is_safe_url_destination() across all 12 categories:
   - Valid public IPv4
   - Valid public IPv6
   - Loopback addresses
   - Private IPv4 ranges
   - Link-local addresses
   - Unspecified and multicast addresses
   - Reserved or special-purpose addresses
   - IPv4-mapped IPv6 addresses
   - Malformed IP addresses
   - Normal public hostname (example.com)
   - Hostname whose DNS resolution fails
   - Hostname with mixed public and non-public DNS responses
"""

import sys
import os
import platform
import socket
import ipaddress
import urllib.parse
from unittest.mock import patch

# Ensure root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.feature_extractor import _is_public_ip, _is_safe_url_destination
from src.pipeline_router import check_url_resource, route_url


def diagnose_environment():
    print("=" * 70)
    print("SECTION 3: PYTHON ENVIRONMENT AND DNS STABILITY")
    print("=" * 70)
    print(f"Python Version:       {sys.version}")
    print(f"Python Executable:    {sys.executable}")
    print(f"Operating System:     {platform.platform()} ({platform.system()} {platform.release()})")

    # Check repeated DNS resolutions for example.com
    print("\nRepeated DNS resolution test for 'example.com' (5 attempts):")
    for attempt in range(1, 6):
        try:
            addrs = socket.getaddrinfo("example.com", None)
            ips = sorted(list(set(a[4][0] for a in addrs)))
            print(f"  Attempt {attempt}: Success -> {ips}")
        except Exception as e:
            print(f"  Attempt {attempt}: Failed -> {type(e).__name__}: {e}")


def trace_url_safety(target_url: str):
    print("\n" + "=" * 70)
    print(f"SECTION 2: STEP-BY-STEP TRACE FOR {target_url}")
    print("=" * 70)

    # 1. Parsing & Scheme
    parsed = urllib.parse.urlparse(target_url)
    scheme = parsed.scheme
    hostname = parsed.hostname
    print(f"1. URL Parsing:")
    print(f"   Parsed Scheme:   {scheme!r} (Valid http/https: {scheme.lower() in ('http', 'https')})")
    print(f"   Parsed Hostname: {hostname!r}")

    if scheme.lower() not in ("http", "https"):
        print("   -> FAILING BRANCH: Scheme validation failed.")
        return False, "Scheme validation failed"

    if not hostname:
        print("   -> FAILING BRANCH: Missing hostname.")
        return False, "Missing hostname"

    # 2. Hostname string check
    hostname_lower = hostname.lower()
    is_blocked_name = hostname_lower in ("localhost", "127.0.0.1", "::1")
    print(f"2. Hostname Name Check: {hostname_lower!r} in ('localhost', '127.0.0.1', '::1') -> {is_blocked_name}")
    if is_blocked_name:
        print("   -> FAILING BRANCH: Blocked hostname string.")
        return False, "Blocked hostname string"

    # 3. IP literal check
    is_ip_literal = False
    try:
        ip = ipaddress.ip_address(hostname)
        is_ip_literal = True
        print(f"3. IP-Literal Check: Hostname IS IP literal ({ip})")
        res_pub = _is_public_ip(str(ip))
        print(f"   _is_public_ip({ip}) -> {res_pub}")
        if not res_pub:
            print("   -> FAILING BRANCH: Non-public IP literal.")
            return False, "Non-public IP literal"
        return True, "Allowed public IP literal"
    except ValueError:
        print(f"3. IP-Literal Check: Hostname is NOT an IP literal.")

    # 4. DNS resolution
    print(f"4. DNS Resolution via socket.getaddrinfo({hostname!r}, None):")
    resolved_records = []
    dns_exception = None
    try:
        resolved_records = socket.getaddrinfo(hostname, None)
        print(f"   socket.getaddrinfo returned {len(resolved_records)} records.")
    except Exception as e:
        dns_exception = e
        print(f"   socket.getaddrinfo RAISED EXCEPTION: {type(e).__name__}: {e}")

    if dns_exception:
        # Check fallback
        is_private_suffix = any(hostname_lower.endswith(sfx) for sfx in (".local", ".internal", ".localhost"))
        print(f"   DNS Exception Fallback Check: is_private_suffix={is_private_suffix}")
        if is_private_suffix:
            print("   -> FAILING BRANCH: DNS failed and private domain suffix detected.")
            return False, "DNS failed with private suffix"
        print("   -> Current behavior returns True for unresolvable public-looking hostnames.")
        return True, "Allowed via DNS exception fallback"

    # Extract unique IPs
    unique_ips = []
    seen = set()
    for addr in resolved_records:
        ip_str = addr[4][0]
        if ip_str not in seen:
            seen.add(ip_str)
            unique_ips.append(ip_str)

    print(f"   Resolved Distinct IPs: {unique_ips}")

    # 5. Inspect each resolved address
    print("5. Inspection of Resolved Addresses:")
    all_public = True
    failing_ip = None
    for ip_str in unique_ips:
        print(f"\n   --- Address: {ip_str} ---")
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            print(f"       Parsed:           IPv{ip_obj.version}")
            print(f"       is_private:       {ip_obj.is_private}")
            print(f"       is_loopback:      {ip_obj.is_loopback}")
            print(f"       is_link_local:    {ip_obj.is_link_local}")
            print(f"       is_reserved:      {ip_obj.is_reserved}")
            print(f"       is_multicast:     {ip_obj.is_multicast}")
            print(f"       is_unspecified:   {ip_obj.is_unspecified}")
            print(f"       is_global:        {ip_obj.is_global}")
            pub = _is_public_ip(ip_str)
            print(f"       _is_public_ip():  {pub}")
            if not pub:
                all_public = False
                failing_ip = (ip_str, ip_obj)
        except ValueError as ve:
            print(f"       ipaddress.ip_address({ip_str!r}) RAISED ValueError: {ve}")
            all_public = False
            failing_ip = (ip_str, None)

    if not all_public:
        print(f"\n   -> FAILING BRANCH: Resolved address {failing_ip[0]} failed _is_public_ip() check.")
        return False, f"Resolved address {failing_ip[0]} is non-public"

    print("\n   -> All resolved addresses passed _is_public_ip(). Destination is SAFE.")
    return True, "Safe URL destination"


def test_validator_categories():
    print("\n" + "=" * 70)
    print("SECTION 4: VALIDATOR TESTING ACROSS ALL 12 ISOLATED CATEGORIES")
    print("=" * 70)

    categories = [
        # (category_name, test_ip_or_url, expected_is_public_ip, expected_safe_url, is_url)
        ("1. Valid Public IPv4", "93.184.216.34", True, True, False),
        ("2. Valid Public IPv6", "2606:2800:220:1:248:1893:25c8:1946", True, True, False),
        ("3a. Loopback IPv4 (127.0.0.1)", "127.0.0.1", False, False, False),
        ("3b. Loopback IPv4 (127.0.0.2)", "127.0.0.2", False, False, False),
        ("3c. Loopback IPv6 (::1)", "::1", False, False, False),
        ("4a. Private IPv4 (10.0.0.1)", "10.0.0.1", False, False, False),
        ("4b. Private IPv4 (172.16.0.1)", "172.16.0.1", False, False, False),
        ("4c. Private IPv4 (172.31.255.255)", "172.31.255.255", False, False, False),
        ("4d. Private IPv4 (192.168.1.1)", "192.168.1.1", False, False, False),
        ("5a. Link-local IPv4 (169.254.1.1)", "169.254.1.1", False, False, False),
        ("5b. Link-local IPv6 (fe80::1)", "fe80::1", False, False, False),
        ("6a. Unspecified IPv4 (0.0.0.0)", "0.0.0.0", False, False, False),
        ("6b. Unspecified IPv6 (::)", "::", False, False, False),
        ("6c. Multicast IPv4 (224.0.0.1)", "224.0.0.1", False, False, False),
        ("6d. Multicast IPv6 (ff02::1)", "ff02::1", False, False, False),
        ("7a. Reserved IPv4 (240.0.0.1)", "240.0.0.1", False, False, False),
        ("7b. TEST-NET-1 (192.0.2.1)", "192.0.2.1", False, False, False),
        ("7c. TEST-NET-2 (198.51.100.1)", "198.51.100.1", False, False, False),
        ("7d. TEST-NET-3 (203.0.113.1)", "203.0.113.1", False, False, False),
        ("7e. Documentation IPv6 (2001:db8::1)", "2001:db8::1", False, False, False),
        ("8a. IPv4-mapped loopback (::ffff:127.0.0.1)", "::ffff:127.0.0.1", False, False, False),
        ("8b. IPv4-mapped private (::ffff:192.168.1.1)", "::ffff:192.168.1.1", False, False, False),
        ("8c. IPv4-mapped public (::ffff:93.184.216.34)", "::ffff:93.184.216.34", True, True, False),
        ("9. Malformed IP (999.999.999.999)", "999.999.999.999", False, False, False),
    ]

    for name, val, exp_pub, exp_safe, is_url in categories:
        pub_res = _is_public_ip(val)
        url = val if is_url else f"http://{val}/"
        safe_res = _is_safe_url_destination(url, resolve_dns=False)
        pub_ok = (pub_res == exp_pub)
        safe_ok = (safe_res == exp_safe)
        status = "PASS" if (pub_ok and safe_ok) else "FAIL"
        print(f"[{status}] {name:42s} | _is_public_ip: {str(pub_res):5s} (exp {str(exp_pub):5s}) | safe: {str(safe_res):5s} (exp {str(exp_safe):5s})")

    # Hostname Mock Tests
    print("\nHostname Isolated Tests with Controlled DNS Mocks:")

    # 10. Normal public hostname
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0))
        ]
        res = _is_safe_url_destination("https://example.com/")
        print(f"[{'PASS' if res else 'FAIL'}] 10. Normal public hostname (example.com with public IPs) -> {res} (expected True)")

    # 11. DNS resolution fails
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.side_effect = socket.gaierror(-2, "Name or service not known")
        res_public_name = _is_safe_url_destination("https://unresolvable-public-name.org/")
        res_private_name = _is_safe_url_destination("https://internal-service.local/")
        print(f"[*] 11a. DNS resolution failure for public name -> {res_public_name}")
        print(f"[*] 11b. DNS resolution failure for .local name  -> {res_private_name} (expected False)")

    # 12. Hostname resolving to a mixture of public and non-public addresses
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),      # Public
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),          # Loopback
        ]
        res_mixed = _is_safe_url_destination("https://mixed-resolution.com/")
        print(f"[{'PASS' if not res_mixed else 'FAIL'}] 12. Mixed public & loopback DNS response -> {res_mixed} (expected False)")

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.66.147.243", 0)),    # Public
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),          # Private
        ]
        res_mixed_priv = _is_safe_url_destination("https://mixed-private.com/")
        print(f"[{'PASS' if not res_mixed_priv else 'FAIL'}] 12b. Mixed public & private (10.0.0.1) -> {res_mixed_priv} (expected False)")


if __name__ == "__main__":
    diagnose_environment()
    trace_url_safety("https://example.com/")
    test_validator_categories()
