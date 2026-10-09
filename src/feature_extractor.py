"""
Phishing Detection Feature Extraction Module.

Section 1: URL String / URL Structure Features
This section implements exactly 8 features based strictly on the authoritative rules:
1. having_IP_Address
2. URL_Length
3. Shortining_Service
4. having_At_Symbol
5. double_slash_redirecting
6. Prefix_Suffix
7. having_Sub_Domain
8. HTTPS_token

Section 2: HTTPS / Network-Level Features
This section implements exactly 3 features:
1. SSLfinal_State       (Position 8)
2. port                 (Position 9)
3. Redirect             (Position 18)
"""

from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from typing import Dict, Optional

# Explicit 2-letter country code Top Level Domains (ISO 3166-1 alpha-2)
CCTLD_SET = {
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "as", "at", "au",
    "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn",
    "bo", "bq", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch",
    "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj",
    "dk", "dm", "do", "dz", "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk",
    "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp",
    "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie",
    "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh",
    "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls",
    "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mf", "mg", "mh", "mk", "ml", "mm", "mn",
    "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne",
    "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph",
    "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw",
    "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr",
    "ss", "st", "su", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl",
    "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "um", "us", "uy", "uz",
    "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw"
}

# Source-supported shortening domains
SHORTENING_SERVICES = ("tinyurl", "bit.ly")

# Source-specified trusted Certificate Authorities
TRUSTED_CA_LIST = [
    "geotrust",
    "godaddy",
    "network solutions",
    "thawte",
    "comodo",
    "doster",
    "verisign",
]

PREFERRED_PORTS = [80, 443]
RESTRICTED_PORTS = [21, 22, 23, 445, 1433, 1521, 3306, 3389]

PREFERRED_PORT_STATUS: Dict[int, bool] = {
    21: False,     # FTP -> Close
    22: False,     # SSH -> Close
    23: False,     # Telnet -> Close
    80: True,      # HTTP -> Open
    443: True,     # HTTPS -> Open
    445: False,    # SMB -> Close
    1433: False,   # MSSQL -> Close
    1521: False,   # Oracle -> Close
    3306: False,   # MySQL -> Close
    3389: False,   # Remote Desktop -> Close
}

def extract_domain(url: str) -> str:
    """
    Consistently extract the hostname/domain from a URL string.
    Handles schemes or schemeless URLs gracefully.
    """
    if not isinstance(url, str):
        return ""
    url_clean = url.strip()
    if not url_clean:
        return ""

    lowered = url_clean.lower()
    for scheme in ("data:", "javascript:", "mailto:", "about:"):
        if lowered.startswith(scheme):
            return "" 
            
    # If scheme is missing, urlparse might place host into path
    if "://" not in url_clean:
        url_clean = "//" + url_clean

    try:
        parsed = urlparse(url_clean)
        host = parsed.hostname or parsed.netloc or ""
        # Strip port if present in netloc when hostname is empty
        if ":" in host:
            host = host.split(":")[0]
        return host.strip().lower()
    except Exception:
        return ""


# ==============================================================================
# SECTION 1 FEATURES
# ==============================================================================

def extract_having_ip_address(url: str) -> int:
    """
    Feature 1: having_IP_Address
    Inspect the domain/host portion of the URL.
    Return:
      -1 if the domain is an IP address or hexadecimal IP representation.
       1 otherwise.
    """
    domain = extract_domain(url)
    if not domain:
        return 1

    # Standard IP check (IPv4 / IPv6)
    try:
        ipaddress.ip_address(domain)
        return -1
    except ValueError:
        pass

    # Check for dotted hexadecimal IP representations (e.g., 0x58.0xCC.0xCA.0x62)
    hex_ip_pattern = r"^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$"
    if re.match(hex_ip_pattern, domain):
        return -1

    # Check for single integer/dword IP representation (e.g. 0x7f000001 or pure numbers)
    if domain.startswith("0x") and re.match(r"^0x[0-9a-fA-F]+$", domain):
        return -1

    return 1


def extract_url_length(url: str) -> int:
    """
    Feature 2: URL_Length
    Calculate the total number of characters in the complete URL string.
    Return:
       1 if URL length < 54
       0 if 54 <= URL length <= 75
      -1 if URL length > 75
    """
    length = len(url)
    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


def extract_shortining_service(url: str) -> int:
    """
    Feature 3: Shortining_Service
    Detect tinyurl or bit.ly domains (case-insensitive).
    Return:
      -1 if URL uses one of these shortening domains.
       1 otherwise.
    """
    domain = extract_domain(url)
    for service in SHORTENING_SERVICES:
        if service in domain:
            return -1
    return 1


def extract_having_at_symbol(url: str) -> int:
    """
    Feature 4: having_At_Symbol
    Check whether the complete URL contains '@'.
    Return:
      -1 if '@' exists.
       1 otherwise.
    """
    return -1 if "@" in url else 1


def extract_double_slash_redirecting(url: str) -> int:
    """
    Feature 5: double_slash_redirecting
    Find the position of the LAST occurrence of '//' in the URL.
    Return:
      -1 if the position of the last '//' is greater than 7.
       1 otherwise.
    """
    last_pos = url.rfind("//")
    if last_pos > 7:
        return -1
    return 1


def extract_prefix_suffix(url: str) -> int:
    """
    Feature 6: Prefix_Suffix
    Check whether '-' exists in the domain/hostname.
    Return:
      -1 if '-' exists in the domain.
       1 otherwise.
    """
    domain = extract_domain(url)
    return -1 if "-" in domain else 1


def extract_having_sub_domain(url: str) -> int:
    """
    Feature 7: having_Sub_Domain
    Rule:
    1. Omit 'www.' from the domain.
    2. Omit the ccTLD (if present at the end).
    3. Count the remaining dots in the domain part.
    Return:
       1 if remaining dots == 1
       0 if remaining dots == 2
      -1 if remaining dots > 2 (or < 1)
    """
    domain = extract_domain(url)
    if not domain:
        return 1

    # 1. Omit "www."
    if domain.startswith("www."):
        domain = domain[4:]

    # 2. Omit ccTLD if the last part is a 2-letter country code
    parts = domain.split(".")
    if len(parts) > 1 and parts[-1].lower() in CCTLD_SET:
        parts = parts[:-1]

    # 3. Count the remaining dots
    # remaining dots between remaining parts is len(parts) - 1
    remaining_dots = len(parts) - 1

    if remaining_dots == 1:
        return 1
    elif remaining_dots == 2:
        return 0
    else:
        # > 2 dots -> -1
        return -1


def extract_https_token(url: str) -> int:
    """
    Feature 8: HTTPS_token
    Check whether the string 'http' or 'https' occurs inside the domain portion.
    The normal URL scheme does NOT count.
    Return:
      -1 if HTTP/HTTPS appears inside the domain.
       1 otherwise.
    """
    domain = extract_domain(url)
    domain_lower = domain.lower()
    if "http" in domain_lower or "https" in domain_lower:
        return -1
    return 1


# ==============================================================================
# SECTION 2 FEATURES (HTTPS / NETWORK-LEVEL)
# ==============================================================================

# ------------------------------------------------------------------------------
# Feature 1 (Position 8): SSLfinal_State
# ------------------------------------------------------------------------------

def is_trusted_ca(issuer_str: str) -> bool:
    """Check if the issuer string contains one of the 7 trusted CA names."""
    if not issuer_str:
        return False
    issuer_lower = issuer_str.lower()
    for ca in TRUSTED_CA_LIST:
        if ca in issuer_lower:
            return True
    return False


def decide_ssl_final_state(is_https: bool, issuer_str: str, cert_age_years: float) -> int:
    """
    Deterministic decision function for SSLfinal_State.
    Rule:
    CASE 1:
      URL uses HTTPS
      AND certificate issuer is trusted
      AND certificate age is >= 1 year
      -> 1
    CASE 2:
      URL uses HTTPS
      AND certificate issuer is NOT trusted
      -> 0
    CASE 3:
      Otherwise (non-HTTPS, or HTTPS with trusted issuer but age < 1 year)
      -> -1
    """
    if not is_https:
        return -1

    if is_trusted_ca(issuer_str):
        if cert_age_years >= 1.0:
            return 1
        else:
            return -1
    else:
        return 0


def fetch_certificate_info(hostname: str, timeout: float = 3.0):
    """
    Connect to hostname via TLS and retrieve issuer and certificate age.

    Returns:
        (issuer_str, cert_age_years) on success
        (None, None) on certificate/network error
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    return None, None

                # Extract issuer
                issuer_parts = []
                for entry in cert.get("issuer", ()):
                    for k, v in entry:
                        issuer_parts.append(f"{k}={v}")

                issuer_str = ", ".join(issuer_parts)

                # Extract certificate issue date
                not_before_str = cert.get("notBefore")

                if not not_before_str:
                    return issuer_str, 0.0

                # Convert certificate issue date using Python's SSL helper
                not_before_timestamp = ssl.cert_time_to_seconds(not_before_str)

                # Calculate certificate age
                age_seconds = time.time() - not_before_timestamp
                cert_age_years = (age_seconds / 86400.0) / 365.25

                return issuer_str, cert_age_years

    except Exception:
        return None, None


def extract_ssl_final_state(url: str, timeout: float = 3.0) -> int:
    """
    Feature: SSLfinal_State (Position 8)
    Inspects TLS certificate for HTTPS URLs.
    Conservative error behavior: returns -1 if non-HTTPS or connection/cert fails.
    """
    if not isinstance(url, str):
        return -1

    parsed = urlparse(url if "://" in url else "http://" + url)
    is_https = (parsed.scheme.lower() == "https")
    if not is_https:
        return -1

    hostname = extract_domain(url)
    if not hostname:
        return -1

    issuer_str, cert_age_years = fetch_certificate_info(hostname, timeout=timeout)
    if issuer_str is None:
        # Certificate inspection failed / unreachable / untrusted TLS handshake failure
        # Handled explicitly: cannot be classified as legitimate. Returns -1.
        return -1

    return decide_ssl_final_state(is_https=True, issuer_str=issuer_str, cert_age_years=cert_age_years)


# ------------------------------------------------------------------------------
# Feature 2 (Position 9): port
# ------------------------------------------------------------------------------

def check_port_open(
    hostname: str,
    port: int,
    timeout: float = 1.0
) -> Optional[bool]:
    """
    Check whether a TCP port is open.

    Returns:
        True  -> port is confirmed OPEN
        False -> port is confirmed CLOSED
        None  -> port status is UNKNOWN because the status
                 could not be determined reliably
    """

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ):
            return True

    except ConnectionRefusedError:
        # The host actively refused the connection.
        # This is strong evidence that the port is closed.
        return False

    except socket.timeout:
        # Timeout does not reliably distinguish between
        # filtered and closed ports.
        return None

    except OSError:
        # Network/DNS/routing/etc. error.
        # Do not incorrectly treat this as "closed".
        return None


def decide_port_status(
    port_states: Dict[int, Optional[bool]]
) -> int:
    """
    Deterministic decision function for the port feature.

    Source table's preferred configuration:

        21    -> Closed
        22    -> Closed
        23    -> Closed
        80    -> Open
        443   -> Open
        445   -> Closed
        1433  -> Closed
        1521  -> Closed
        3306  -> Closed
        3389  -> Closed

    Decision:

        If ALL actual port states match their corresponding
        preferred states:
            return 1  (Legitimate)

        If ANY known port conflicts with its preferred state:
            return -1 (Phishing)

        If any port status is UNKNOWN:
            return -1 because the complete preferred configuration
            cannot be verified.

    Note:
        The source sentence saying
        "Preferred Status -> Phishing"
        is being treated as a typo, as agreed.
    """

    for port, preferred_state in PREFERRED_PORT_STATUS.items():

        actual_state = port_states.get(port)

        # Cannot verify the required state.
        if actual_state is None:
            return -1

        # Actual state does not match preferred state.
        if actual_state != preferred_state:
            return -1

    # Every specified port matches its preferred status.
    return 1


def extract_port(
    url: str,
    timeout: float = 1.0
) -> int:
    """
    Feature: port (Position 9)

    Checks the actual server-side TCP status of the
    ten ports specified by the source table.

    Returns:
        1  -> all ten ports match their preferred status
        -1 -> otherwise
    """

    if not isinstance(url, str) or not url.strip():
        return -1

    # Use the existing domain extraction function from the
    # feature extractor. Do not duplicate URL parsing logic.
    hostname = extract_domain(url)

    if not hostname:
        return -1

    port_states: Dict[int, Optional[bool]] = {}

    # Check every port specified by the source table.
    for port in PREFERRED_PORT_STATUS:
        port_states[port] = check_port_open(
            hostname,
            port,
            timeout=timeout
        )

    return decide_port_status(port_states)

# ------------------------------------------------------------------------------
# Feature 3 (Position 18): Redirect
# ------------------------------------------------------------------------------

class RedirectTracker(HTTPRedirectHandler):
    """Custom HTTPRedirectHandler that counts HTTP redirects in the chain."""
    def __init__(self):
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def decide_redirect(redirect_count: int) -> int:
    """
    Deterministic decision function for Redirect.
    Rule:
    -  1 if redirect_count <= 1  (0 -> 1, 1 -> 1)
    -  0 if redirect_count is 2 or 3  (2 -> 0, 3 -> 0)
    - -1 if redirect_count >= 4  (4 -> -1, 5 -> -1, etc.)
    """
    if redirect_count <= 1:
        return 1
    elif redirect_count <= 3:
        return 0
    else:
        return -1


def extract_redirect(url: str, timeout: float = 3.0) -> int:
    """
    Feature: Redirect (Position 18)
    Counts the number of HTTP redirects using actual response chain.
    Conservative error behavior: returns -1 on redirect failure or network failure.
    """
    if not isinstance(url, str):
        return -1

    url_to_open = url.strip()
    if not url_to_open:
        return -1
    if "://" not in url_to_open:
        url_to_open = "http://" + url_to_open

    tracker = RedirectTracker()
    opener = build_opener(tracker)
    req = Request(url_to_open, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    try:
        with opener.open(req, timeout=timeout) as resp:
            return decide_redirect(tracker.redirect_count)
    except HTTPError as e:
        # An HTTP error might still have followed redirects before failing
        return decide_redirect(tracker.redirect_count)
    except (URLError, socket.timeout):
        # Unreachable host or network failure
        return -1


# ==============================================================================
# SECTION 3 FEATURES (HTML / PAGE-CONTENT)
# ==============================================================================

from html.parser import HTMLParser
from urllib.parse import urljoin


class SimpleHTMLTagExtractor(HTMLParser):
    """
    Standard library HTML parser to collect relevant elements and attributes
    for Section 3 feature extraction without external dependencies.
    """
    def __init__(self):
        super().__init__()
        self.favicons = []
        self.embedded_objects = []
        self.anchors = []
        self.tag_links = []
        self.forms = []
        self.has_iframe = False

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        attrs_dict = {k.lower(): (v if v is not None else "") for k, v in attrs}

        if tag_lower == "iframe":
            self.has_iframe = True

        elif tag_lower == "link":
            rel = attrs_dict.get("rel", "").lower()
            href = attrs_dict.get("href", "").strip()
            if "icon" in rel and href:
                self.favicons.append(href)
            if href:
                self.tag_links.append(href)

        elif tag_lower in ("img", "video", "audio"):
            src = attrs_dict.get("src", "").strip()
            if src:
                self.embedded_objects.append(src)

        elif tag_lower == "a":
            href = attrs_dict.get("href", None)
            self.anchors.append(href)

        elif tag_lower == "script":
            src = attrs_dict.get("src", "").strip()
            if src:
                self.tag_links.append(src)

        elif tag_lower == "meta":
            content = attrs_dict.get("content", "").strip()

            # Only collect content that clearly represents a URL/resource.
            if content:
                content_lower = content.lower()

                if (
                    content_lower.startswith("http://")
                    or content_lower.startswith("https://")
                    or content_lower.startswith("//")
                    or content_lower.startswith("/")
                ):
                    self.tag_links.append(content)

        elif tag_lower == "form":
            action = attrs_dict.get("action", None)
            self.forms.append(action)


def _is_external_resource(resource_url: str, page_url: str) -> bool:
    """
    Resolve relative resource URL against page_url and determine if hostnames differ.
    Comparison is case-insensitive.
    """
    if not resource_url or not page_url:
        return False
    resolved = urljoin(page_url, resource_url.strip())
    res_domain = extract_domain(resolved)
    page_domain = extract_domain(page_url)
    if not res_domain or not page_domain:
        return False
    return res_domain.lower() != page_domain.lower()


def extract_favicon(html: str, page_url: str) -> int:
    """
    Feature 1 (Position 11): Favicon
    Rule:
    - -1 if favicon is loaded from an external domain
    -  1 otherwise (no favicon, or same-domain favicon)
    """
    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()
    try:
        parser.feed(html)
    except Exception:
        return 1

    if not parser.favicons:
        return 1

    for icon_url in parser.favicons:
        if _is_external_resource(icon_url, page_url):
            return -1

    return 1


def extract_request_url(html: str, page_url: str) -> int:
    """
    Feature 2 (Position 12): Request_URL
    Inspects embedded objects: images, videos, sounds (<img>, <video>, <audio>).
    percentage = external_objects / total_objects * 100
    Return:
       1 if percentage < 22 (or total_objects == 0)
       0 if 22 <= percentage <= 61
      -1 if percentage > 61
    """
    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()
    try:
        parser.feed(html)
    except Exception:
        return 1

    total_objects = len(parser.embedded_objects)
    if total_objects == 0:
        return 1

    external_count = 0
    for obj_url in parser.embedded_objects:
        if _is_external_resource(obj_url, page_url):
            external_count += 1

    percentage = (external_count / total_objects) * 100.0

    if percentage < 22.0:
        return 1
    elif percentage <= 61.0:
        return 0
    else:
        return -1


def extract_url_of_anchor(html: str, page_url: str) -> int:
    """
    Feature 3 (Position 13): URL_of_Anchor

    Source rule:
    - An anchor is suspicious if it points to a different/external domain.
    - An anchor is also suspicious for the explicitly specified
      non-functional destinations:
        # 
        #content
        #skip
        javascript:void(0)

    Percentage:
        suspicious anchors / total anchors * 100

    Return:
        1  if percentage < 31
        0  if 31 <= percentage <= 67
        -1 if percentage > 67
    """

    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()

    try:
        parser.feed(html)
    except Exception:
        return 1

    total_anchors = len(parser.anchors)

    if total_anchors == 0:
        return 1

    suspicious_count = 0

    for href in parser.anchors:

        # The source explicitly identifies these destinations
        # as non-functional/suspicious.
        if href is None:
            continue

        href_clean = href.strip()
        href_lower = href_clean.lower()

        # Explicit non-functional destinations from the source.
        if href_clean in ("#", "#content", "#skip"):
            suspicious_count += 1
            continue

        # Explicit JavaScript void destination from the source.
        if href_lower in (
            "javascript:void(0)",
            "javascript::void(0)",
        ):
            suspicious_count += 1
            continue

        # Different/external domain.
        if _is_external_resource(href_clean, page_url):
            suspicious_count += 1

    percentage = (suspicious_count / total_anchors) * 100.0

    if percentage < 31.0:
        return 1
    elif percentage <= 67.0:
        return 0
    else:
        return -1


def extract_links_in_tags(html: str, page_url: str) -> int:
    """
    Feature 4 (Position 14): Links_in_tags
    Inspects links in <meta>, <script>, <link>.
    percentage = external_tag_links / total_relevant_tag_links * 100
    Return:
       1 if percentage < 17 (or total == 0)
       0 if 17 <= percentage <= 81
      -1 if percentage > 81
    """
    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()
    try:
        parser.feed(html)
    except Exception:
        return 1

    total_links = len(parser.tag_links)
    if total_links == 0:
        return 1

    external_count = 0
    for link_url in parser.tag_links:
        if _is_external_resource(link_url, page_url):
            external_count += 1

    percentage = (external_count / total_links) * 100.0

    if percentage < 17.0:
        return 1
    elif percentage <= 81.0:
        return 0
    else:
        return -1


def _classify_sfh_action(action: str | None, page_url: str) -> int:
    """
    Classify ONE form action according to the source document.

    Source rule:
        empty or about:blank -> -1 (Phishing)
        different/external domain -> 0 (Suspicious)
        otherwise -> 1 (Legitimate)
    """

    if action is None:
        return -1

    action_clean = action.strip()

    if action_clean == "":
        return -1

    if action_clean.lower() == "about:blank":
        return -1

    if _is_external_resource(action_clean, page_url):
        return 0

    return 1


def extract_sfh(html: str, page_url: str) -> int:
    """
    Feature 5 (Position 15): SFH (Server Form Handler)

    Source rule:
        -1 = SFH is empty or about:blank
         0 = SFH refers to a different/external domain
         1 = otherwise

    Multiple-form handling:
        The source document does not specify how multiple forms
        should be aggregated. Therefore, forms are evaluated
        individually and the first form in document order is used.

    No forms:
        Return 1 as the practical "otherwise" behavior.
    """

    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()

    try:
        parser.feed(html)
    except Exception:
        return 1

    if not parser.forms:
        return 1

    # The source does not define an aggregation rule for multiple forms.
    # Use the first form in document order rather than inventing
    # a priority rule between -1, 0, and 1.
    first_action = parser.forms[0]

    return _classify_sfh_action(first_action, page_url)


def extract_iframe(html: str) -> int:
    """
    Feature 6 (Position 17): Iframe
    Rule:
      -1 if the webpage contains ANY <iframe> tag
       1 otherwise
    """
    if not html:
        return 1

    parser = SimpleHTMLTagExtractor()
    try:
        parser.feed(html)
    except Exception:
        return 1

    return -1 if parser.has_iframe else 1


def fetch_webpage_static(url: str, timeout: float = 5.0) -> tuple[str, str]:
    """
    Fetch static webpage HTML using standard library HTTP client (urllib).
    Follows normal HTTP redirects and returns (html_content, final_url).

    Raises URLError, HTTPError, socket.timeout, or ValueError on failure.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    url_to_open = url.strip()
    if "://" not in url_to_open:
        url_to_open = "http://" + url_to_open

    req = Request(
        url_to_open,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )

    with build_opener().open(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        charset = resp.headers.get_content_charset() or "utf-8"
        raw_bytes = resp.read()
        try:
            html = raw_bytes.decode(charset, errors="replace")
        except Exception:
            html = raw_bytes.decode("utf-8", errors="replace")
        return html, final_url


def fetch_webpage(url: str, timeout: float = 10.0) -> tuple[str, str]:
    """
    Fetch webpage HTML using Playwright to retrieve browser-rendered DOM,
    allowing elements inserted by client-side JavaScript to be detected.

    Requirements:
    - Normalizes URL.
    - Launches Chromium in headless mode.
    - Navigates with finite timeout (10,000 ms).
    - Uses wait_until='domcontentloaded'.
    - Bounded rendering wait (e.g. 500 ms) for ordinary page scripts to run.
    - Retrieves rendered DOM via page.content() and final URL via page.url.
    - Always closes browser in a finally block.
    - Falls back to fetch_webpage_static if Playwright fails or is unavailable.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    url_to_open = url.strip()
    if "://" not in url_to_open:
        url_to_open = "http://" + url_to_open

    # Attempt Playwright rendered DOM retrieval
    try:
        from playwright.sync_api import sync_playwright

        timeout_ms = int(timeout * 1000)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(url_to_open, timeout=timeout_ms, wait_until="domcontentloaded")
                # Bounded short rendering wait for scripts to execute
                page.wait_for_timeout(500)
                html = page.content()
                final_url = page.url
                return html, final_url
            finally:
                browser.close()
    except Exception:
        # Fallback to static urllib retrieval if Playwright is unavailable,
        # browser launch fails, or rendering raises an exception.
        return fetch_webpage_static(url_to_open, timeout=min(timeout, 5.0))
