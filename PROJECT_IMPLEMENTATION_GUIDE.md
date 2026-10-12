# Project Implementation Guide: Phishing Detection & Threat Intelligence Platform

This document serves as the comprehensive implementation guide and technical reference for the **Phishing Detection and Threat Intelligence Platform**. It explains the system's architecture, data flow, feature engineering mechanics, machine learning inference pipeline, vector database integration, statistical modeling, recommendation rules, and user interface.

---

## Table of Contents

1. [High-Level Architecture & System Flow](#1-high-level-architecture--system-flow)
2. [Network & Connection Features: `SSLfinal_State` and `port`](#2-network--connection-features-sslfinal_state-and-port)
   - [2.1. Feature 8: `SSLfinal_State`](#21-feature-8-sslfinal_state)
   - [2.2. Feature 9: `port`](#22-feature-9-port)
3. [HTML-Based Features (DOM & Content Inspection)](#3-html-based-features-dom--content-inspection)
   - [3.1. `Favicon` (Position 11)](#31-favicon-position-11)
   - [3.2. `Request_URL` (Position 12)](#32-request_url-position-12)
   - [3.3. `URL_of_Anchor` (Position 13)](#33-url_of_anchor-position-13)
   - [3.4. `Links_in_tags` (Position 14)](#34-links_in_tags-position-14)
   - [3.5. `SFH` - Server Form Handler (Position 15)](#35-sfh---server-form-handler-position-15)
   - [3.6. `Iframe` (Position 17)](#36-iframe-position-17)
4. [JavaScript-Based & Browser-Behavior Features](#4-javascript-based--browser-behavior-features)
   - [4.1. `Redirect` (Position 18)](#41-redirect-position-18)
   - [4.2. `Submitting_to_email` (Position 16)](#42-submitting_to_email-position-16)
   - [4.3. `on_mouseover` (Position 19)](#43-on_mouseover-position-19)
   - [4.4. `RightClick` (Position 20)](#44-rightclick-position-20)
5. [Feature Vector Construction & Dual Prediction Pipelines](#5-feature-vector-construction--dual-prediction-pipelines)
   - [5.1. Input Validation & Safe Destination Pre-checks](#51-input-validation--safe-destination-pre-checks)
   - [5.2. Adaptive Routing: Pipeline A vs. Pipeline B](#52-adaptive-routing-pipeline-a-vs-pipeline-b)
   - [5.3. Feature Ordering & Schema Contracts](#53-feature-ordering--schema-contracts)
   - [5.4. Random Forest Inference & Decision Thresholds](#54-random-forest-inference--decision-thresholds)
6. [Threat Intelligence Vector Database (ChromaDB)](#6-threat-intelligence-vector-database-chromadb)
   - [6.1. Collections & Data Isolation](#61-collections--data-isolation)
   - [6.2. Strict Privacy & Anonymization](#62-strict-privacy--anonymization)
   - [6.3. Idempotent Ingestion & State Transitions](#63-idempotent-ingestion--state-transitions)
7. [Analytics Engine: Statistical Profiling, Clustering & Rarity](#7-analytics-engine-statistical-profiling-clustering--rarity)
   - [7.1. Frequency Distributions & Signal Ranking](#71-frequency-distributions--signal-ranking)
   - [7.2. Unsupervised KMeans Clustering](#72-unsupervised-kmeans-clustering)
   - [7.3. Rarity & Unusual Pattern Detection](#73-rarity--unusual-pattern-detection)
   - [7.4. Feature Co-occurrence Matrix](#74-feature-co-occurrence-matrix)
   - [7.5. Data Quality Auditing](#75-data-quality-auditing)
8. [Defensive Recommendation Engine: 20-Rule Specification](#8-defensive-recommendation-engine-20-rule-specification)
9. [Streamlit UI Dashboard: Component-by-Component Mapping](#9-streamlit-ui-dashboard-component-by-component-mapping)
   - [9.1. View 1: URL Input](#91-view-1-url-input)
   - [9.2. View 2: Prediction Result](#92-view-2-prediction-result)
   - [9.3. View 3: Threat Activity Dashboard](#93-view-3-threat-activity-dashboard)
   - [9.4. How to Trace Any Dashboard Metric to Source Code](#94-how-to-trace-any-dashboard-metric-to-source-code)
10. [File-by-File Implementation Map](#10-file-by-file-implementation-map)
11. [Known Observations & Technical Limitations](#11-known-observations--technical-limitations)

---

## 1. High-Level Architecture & System Flow

The platform operates as a secure, privacy-preserving phishing detection system combining supervised machine learning with an unsupervised vector threat intelligence layer.

```
                    +-----------------------------+
                    |        User Enters URL      |
                    +-----------------------------+
                                   |
                                   v
                    +-----------------------------+
                    |    src.ui_validator.py      |
                    |  (Lightweight Format Check) |
                    +-----------------------------+
                                   |
                                   v
                    +-----------------------------+
                    |   src.pipeline_router.py    |
                    |   (HTTP HEAD/GET Probe &    |
                    |    SSRF Security Validation)|
                    +-----------------------------+
                                  / \
           Responsive HTML 200 OK/   \ Non-HTML, Redirect, Error,
                                /     \ or Non-200 Status
                               v       v
         +-----------------------+   +-----------------------+
         |      Pipeline A       |   |      Pipeline B       |
         |  Full 20-Feature Model|   | Reduced 10-Feature Mod|
         +-----------------------+   +-----------------------+
         | extract_features()    |   | extract_10_features() |
         | Models:               |   | Models:               |
         | random_forest.pkl     |   | random_forest_10_     |
         | (Positions 1 to 20)   |   |   features.pkl        |
         +-----------------------+   | (Positions 1 to 10)   |
                     \               +-----------------------+
                      \                         /
                       \                       /
                        v                     v
                    +-----------------------------+
                    |    Supervised Prediction    |
                    |  -1 = Phishing, 1 = Legit   |
                    |  Calibrated Prob Threshold  |
                    +-----------------------------+
                                   |
                   +---------------+---------------+
                   |                               |
                   v (If Legitimate: 1)            v (If Phishing: -1)
         +--------------------+         +------------------------------------+
         | Display Safe Result|         |  src.threat_integration_service.py |
         | (No DB Storage)    |         |  1. Ingest vector into ChromaDB    |
         +--------------------+         |     (NO URLs or hostnames stored)  |
                                        |  2. Recompute Analytics & Clusters |
                                        |  3. Evaluate 20 Recommendation Rule|
                                        |  4. Publish State Transitions Diff |
                                        +------------------------------------+
                                                           |
                                                           v
                                        +------------------------------------+
                                        |  Streamlit Threat Dashboard (UI)   |
                                        |  - Overview & Frequency Metrics    |
                                        |  - Archetypal KMeans Clusters      |
                                        |  - Rule-Based Defensive Action Plan|
                                        +------------------------------------+
```

---

## 2. Network & Connection Features: `SSLfinal_State` and `port`

Both network-level features are implemented in [src/feature_extractor.py](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/feature_extractor.py).

### 2.1. Feature 8: `SSLfinal_State`

- **File & Function**: `src/feature_extractor.py` $\rightarrow$ `extract_ssl_final_state(url, timeout=3.0)` and `decide_ssl_final_state(is_https, issuer_str, cert_age_years)`.
- **Inputs**: Raw URL string, certificate info fetched from live socket connection via `fetch_certificate_info(hostname, timeout=3.0)`.
- **Live Network Verification**: **Yes**. The code connects to the hostname on TCP port 443 via an SSL context socket:
  ```python
  with socket.create_connection((hostname, 443), timeout=timeout) as sock:
      with context.wrap_socket(sock, server_hostname=hostname) as ssock:
          cert = ssock.getpeercert()
  ```
- **Rules & Value Encoding**:
  - **`1` (Legitimate)**: The URL scheme is `https://`, the certificate issuer matches one of the 7 trusted CAs (`trustwave`, `comodo`, `geotrust`, `godaddy`, `verisign`, `digicert`, `identrust`), **AND** the certificate age (`time.time() - notBefore`) is $\ge 1.0\text{ year}$ (365.25 days).
  - **`0` (Suspicious / Intermediate)**: The URL scheme is `https://`, but the certificate issuer is untrusted (self-signed, private, or unrecognized CA).
  - **`-1` (Phishing / Invalid)**: The URL is plain `http://`, or HTTPS handshake fails, host is unreachable, connection times out, or the certificate issuer is trusted but certificate age is $< 1.0\text{ year}$.
- **Fallback / Error Handling**: Conservative error fallback: returns `-1` if the URL is non-HTTPS, socket fails, DNS resolution fails, or certificate data cannot be extracted.
- **Position in Vectors**:
  - **10-Feature Vector**: **Position 9** (index 8).
  - **20-Feature Vector**: **Position 8** (index 7).
- **Influence in Random Forest**: Permutation feature importance confirms that `SSLfinal_State` is the **single most influential feature** in both models, accounting for an average test accuracy drop of **28.1%** in the 10-feature model and **14.3%** in the 20-feature model when shuffled.

---

### 2.2. Feature 9: `port`

- **File & Function**: `src/feature_extractor.py` $\rightarrow$ `extract_port(url, timeout=1.0)` and `decide_port_status(port_states)`.
- **Inputs**: Hostname parsed from URL via `extract_domain(url)`.
- **Live Network Verification**: **Yes**. `extract_port()` does **not** simply parse the port number written in the URL text. Instead, it tests the live server-side TCP status across 10 designated service ports:
  ```python
  PREFERRED_PORT_STATUS = {
      21: False,    # FTP (Preferred: Closed)
      22: False,    # SSH (Preferred: Closed)
      23: False,    # Telnet (Preferred: Closed)
      80: True,     # HTTP (Preferred: Open)
      443: True,    # HTTPS (Preferred: Open)
      445: False,   # SMB (Preferred: Closed)
      1433: False,  # MSSQL (Preferred: Closed)
      1521: False,  # Oracle (Preferred: Closed)
      3306: False,  # MySQL (Preferred: Closed)
      3389: False,  # RDP (Preferred: Closed)
  }
  ```
- **Rules & Value Encoding**:
  - **`1` (Legitimate)**: Every single one of the 10 ports matches its preferred status (ports 80 and 443 are open; database and remote administration ports 21, 22, 23, 445, 1433, 1521, 3306, 3389 are closed).
  - **`-1` (Phishing / Non-preferred)**: Any port violates the expected state (e.g. database/admin port is exposed, or port 80/443 is unreachable), or any port probe times out / returns unknown.
- **Error & Timeout Handling**: Handled via `check_port_open(hostname, port, timeout=1.0)`:
  - If a connection is refused (`ConnectionRefusedError`), it is confirmed **Closed** (`False`).
  - If a connection succeeds, it is confirmed **Open** (`True`).
  - If it times out or encounters `OSError`, status is `None` (Unknown), which fails `decide_port_status` and triggers `-1`.
- **Position in Vectors**:
  - **10-Feature Vector**: **Position 10** (index 9).
  - **20-Feature Vector**: **Position 9** (index 8).

---

## 3. HTML-Based Features (DOM & Content Inspection)

All HTML content features are defined in Section 3 of `src/feature_extractor.py`. They are evaluated only during **Pipeline A (20-feature model)** when the page returns an HTTP 200 response with `Content-Type: text/html`. HTML is retrieved via `fetch_webpage()`, which uses Playwright (headless Chromium) with a bounded 500ms DOM wait, falling back to static `urllib` retrieval if browser automation is unavailable.

### 3.1. `Favicon` (Position 11)
- **Function**: `extract_favicon(html, page_url)`.
- **Rule**:
  - Parses `<link rel="icon" href="...">` or `<link rel="shortcut icon" ...>`.
  - Resolves href relative to `page_url` and compares domain names.
  - Returns **`-1`** if the favicon domain differs from the page domain (external favicon).
  - Returns **`1`** if the favicon is hosted on the same domain or if no favicon tag exists.

### 3.2. `Request_URL` (Position 12)
- **Function**: `extract_request_url(html, page_url)`.
- **Rule**:
  - Collects embedded media objects: `<img>`, `<video>`, `<audio>` sources.
  - Computes: $\text{percentage} = \frac{\text{external embedded objects}}{\text{total embedded objects}} \times 100$.
  - Returns **`1`** if percentage $< 22\%$ (or 0 objects present).
  - Returns **`0`** if $22\% \le \text{percentage} \le 61\%$.
  - Returns **`-1`** if percentage $> 61\%$.

### 3.3. `URL_of_Anchor` (Position 13)
- **Function**: `extract_url_of_anchor(html, page_url)`.
- **Rule**:
  - Inspects all `<a>` tags. An anchor is marked suspicious if:
    1. It points to an external domain.
    2. It points to a placeholder/non-functional target: `#`, `#content`, `#skip`.
    3. It uses empty script triggers: `javascript:void(0)` or `javascript::void(0)`.
  - Computes: $\text{percentage} = \frac{\text{suspicious anchors}}{\text{total anchors}} \times 100$.
  - Returns **`1`** if percentage $< 31\%$ (or 0 anchors present).
  - Returns **`0`** if $31\% \le \text{percentage} \le 67\%$.
  - Returns **`-1`** if percentage $> 67\%$.

### 3.4. `Links_in_tags` (Position 14)
- **Function**: `extract_links_in_tags(html, page_url)`.
- **Rule**:
  - Inspects resource links inside `<meta>`, `<script>`, and `<link>` tags.
  - Computes: $\text{percentage} = \frac{\text{external tag links}}{\text{total relevant tag links}} \times 100$.
  - Returns **`1`** if percentage $< 17\%$ (or 0 tags present).
  - Returns **`0`** if $17\% \le \text{percentage} \le 81\%$.
  - Returns **`-1`** if percentage $> 81\%$.

### 3.5. `SFH` - Server Form Handler (Position 15)
- **Function**: `extract_sfh(html, page_url)`.
- **Rule**:
  - Evaluates the `<form action="...">` attribute of the first form in document order.
  - Returns **`-1`** if the action is empty (`action=""`) or `about:blank`.
  - Returns **`0`** if the action submits to a different/external domain.
  - Returns **`1`** if the action submits locally, or if no forms exist on the page.

### 3.6. `Iframe` (Position 17)
- **Function**: `extract_iframe(html)`.
- **Rule**:
  - Checks whether any `<iframe>` element exists in the HTML document.
  - Returns **`-1`** if at least one `<iframe>` tag is found.
  - Returns **`1`** if no `<iframe>` tag is present.

---

## 4. JavaScript-Based & Browser-Behavior Features

These features are implemented in Section 4 of `src/feature_extractor.py`.

### 4.1. `Redirect` (Position 18)
- **Function**: `extract_redirect(url, timeout=3.0)` and `decide_redirect(redirect_count)`.
- **Mechanism**: Does **not** execute browser JS. Uses a custom Python `urllib.request.HTTPRedirectHandler` (`RedirectTracker`) that hooks into `redirect_request()` to count actual HTTP redirects ($301, 302, 303, 307, 308$).
- **Rule**:
  - Returns **`1`** if redirects $\le 1$ ($0 \rightarrow 1, 1 \rightarrow 1$).
  - Returns **`0`** if redirects are $2$ or $3$.
  - Returns **`-1`** if redirects $\ge 4$, or if network connection fails.

### 4.2. `Submitting_to_email` (Position 16)
- **Function**: `extract_submitting_to_email(html, page_url, session=None)`.
- **Mechanism**: Static parsing with AST-like regex scanners. **Does not execute JavaScript**.
  - Inspects HTML `<form action="mailto:...">` and `<button formaction="mailto:...">`.
  - Gathers inline scripts (`<script>`) and external JS files (up to 20 files, max 1MB each, validated against private IP / SSRF filters).
  - Strips JS comments (`//` and `/* */`) using `_strip_javascript_comments()`.
  - Checks if code dynamically assigns `form.action = 'mailto:...'`, navigates data to mailto (`location.href = 'mailto:...?body=' + data`), or calls `form.submit()` with mailto.
- **Rule**: Returns **`-1`** if mailto submission evidence is detected; **`1`** otherwise.

### 4.3. `on_mouseover` (Position 19)
- **Function**: `extract_on_mouseover(html, page_url, session=None)`.
- **Mechanism**: Inspects inline `onmouseover` event handler attributes and JS code blocks.
  - Searches for status-bar spoofing: `window.status = ...` or `status = '...'`.
  - Uses `_extract_balanced_block()` to ensure the status bar modification is directly scoped inside a `mouseover` / `mouseenter` event listener or callback.
  - Excludes styling changes (e.g. `this.style.color = 'red'`) and tooltips.
- **Rule**: Returns **`-1`** if mouseover status-bar spoofing is present; **`1`** otherwise.

### 4.4. `RightClick` (Position 20)
- **Function**: `extract_right_click(html, page_url, session=None)`.
- **Mechanism**: Inspects event handlers (`oncontextmenu`, `onmousedown`) and scripts.
  - Checks if code binds `event.button == 2` directly to disabling behavior (`return false`, `preventDefault()`, `cancelBubble = true`, `returnValue = false`).
  - Does not flag generic `contextmenu` handlers unless right-click mouse button logic is verified.
- **Rule**: Returns **`-1`** if right-click suppression logic is detected; **`1`** otherwise.

---

## 5. Feature Vector Construction & Dual Prediction Pipelines

### 5.1. Input Validation & Safe Destination Pre-checks
When a URL is submitted in the Streamlit UI or CLI:
1. `src.ui_validator.validate_url_format()` performs structural checks: trims whitespace, rejects internal whitespace, strips scheme, extracts host, and verifies the host is an IP address or a domain with $\ge 1$ dot and a TLD $\ge 2$ characters.
2. `src.pipeline_router._is_safe_url_destination()` verifies SSRF security: blocks `localhost`, `127.0.0.1`, `::1`, private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs, and private suffixes (`.local`, `.internal`).

### 5.2. Adaptive Routing: Pipeline A vs. Pipeline B
`src.pipeline_router.route_url()` issues an HTTP probe using `check_url_resource()` (bounded redirects, 5-second timeout, stream closed before downloading large bodies):
- **Pipeline A (20-Feature Comprehensive Pipeline)**:
  - Selected if HTTP response is **200 OK** AND `Content-Type` is `text/html`.
  - Invokes `extract_features(url)` $\rightarrow$ produces 20 features.
  - Evaluated against `models/random_forest.pkl`.
- **Pipeline B (10-Feature Fast / Structural Pipeline)**:
  - Selected if resource returns non-200 status (403, 404, 500), times out, redirects off-domain, fails SSL handshake, or returns non-HTML media (application/pdf, image/png, etc.).
  - Invokes `extract_10_features(url)` $\rightarrow$ produces 10 URL/network features without downloading HTML.
  - Evaluated against `models/random_forest_10_features.pkl`.

### 5.3. Feature Ordering & Schema Contracts
Contracts are strictly enforced by `src/feature_contract.py`:

```
===================================================================================================
Position | 10-Feature Schema (Pipeline B)       | 20-Feature Schema (Pipeline A)
===================================================================================================
1        | having_IP_Address                    | having_IP_Address
2        | URL_Length                           | URL_Length
3        | Shortining_Service                   | Shortining_Service
4        | having_At_Symbol                     | having_At_Symbol
5        | double_slash_redirecting             | double_slash_redirecting
6        | Prefix_Suffix                        | Prefix_Suffix
7        | having_Sub_Domain                    | having_Sub_Domain
8        | HTTPS_token                          | SSLfinal_State
9        | SSLfinal_State                       | port
10       | port                                 | HTTPS_token
11       | ---                                  | Favicon
12       | ---                                  | Request_URL
13       | ---                                  | URL_of_Anchor
14       | ---                                  | Links_in_tags
15       | ---                                  | SFH
16       | ---                                  | Submitting_to_email
17       | ---                                  | Iframe
18       | ---                                  | Redirect
19       | ---                                  | on_mouseover
20       | ---                                  | RightClick
===================================================================================================
```
*(Notice: In the 10-feature model, URL-string feature `HTTPS_token` is positioned at index 8, with network features `SSLfinal_State` at 9 and `port` at 10).*

### 5.4. Random Forest Inference & Decision Thresholds
- **Model Loading**: Cached in memory via `load_model()` and `load_10_feature_model()` in `src/classifier.py`.
- **Class Probability Extraction**:
  ```python
  probs = model.predict_proba(sample)
  classes_list = list(model.classes_)
  pos_idx = classes_list.index(-1) # Class -1 is Phishing
  phishing_prob = float(probs[0][pos_idx])
  ```
- **Calibrated Decision Threshold**: Set in `models/model_config.json` at **`0.45`**, balancing phishing recall ($>89.6\%$ on 10-feat, $>94.4\%$ on 20-feat) while preventing false alarms on clean traffic.

---

## 6. Threat Intelligence Vector Database (ChromaDB)

Implemented in `src/threat_vector_db.py`.
- **Location**: Local persistent database directory at `chroma_db/chroma.sqlite3`.
- **Collections**:
  1. `phishing_10_features`: Stores 10-dimensional integer vectors.
  2. `phishing_20_features`: Stores 20-dimensional integer vectors.
- **Strict Privacy & Anti-Surveillance Guarantee**:
  - The vector database stores **zero URLs, hostnames, IP addresses, domains, or query strings**.
  - Metadata keys containing `url`, `domain`, `hostname`, `path`, `href`, or `http` are blocked by `insert_phishing_vector()`.
  - Only anonymous categorical feature vectors (`[-1, 1, 0, ...]`), ISO timestamps, model type, and synthetic event IDs (`event_...` or `phish_...`) are persisted.
- **Phishing-Only Filter**: Records are inserted if and only if `prediction_label == -1`. Legitimate predictions (`1`) are discarded immediately.
- **Idempotency**: Repeated calls with the same `event_id` or identical case ID return `duplicate_event` without re-inserting.

---

## 7. Analytics Engine: Statistical Profiling, Clustering & Rarity

The analytics layer (`src/threat_analytics.py`, `src/threat_clustering.py`, `src/threat_data_quality.py`) generates analytical reports stored in `reports/threat_analytics/phishing_10_features/` and `reports/threat_analytics/phishing_20_features/`.

### 7.1. Frequency Distributions & Signal Ranking
- **Denominator**: Total valid phishing records in the collection ($N$).
- **Signal Ranking**: Ranks every individual feature-value condition (e.g. `Prefix_Suffix == -1`). Sorted deterministically by count descending, percentage descending, feature name ascending, and value ascending.

### 7.2. Unsupervised KMeans Clustering
- **Algorithm**: `KMeans(n_clusters=4, random_state=42, n_init=10)` with Euclidean distance on ternary coordinates.
- **Archetype Profiling**: Computes centroids, dominant feature values, and uniformity indicators (`is_uniform = True` if $100\%$ of cluster members share the exact same value).

### 7.3. Rarity & Unusual Pattern Detection
- Identifies unusual vector signatures where total occurrence count $\le \text{rarity\_count\_threshold}$ (default $\le 2$).
- Highlights rare vectors for security threat hunting.

### 7.4. Feature Co-occurrence Matrix
- Evaluates pairwise relationships $(A, B)$ across all features:
  - $\text{Support} = P(A \cap B) = \frac{\text{count}(A \text{ and } B)}{N}$.
  - $\text{Directional Confidence } A \rightarrow B = P(B \mid A) = \frac{\text{count}(A \text{ and } B)}{\text{count}(A)}$.

### 7.5. Data Quality Auditing
- Scans collection records for dimensionality violations, non-finite values, invalid labels, missing timestamps, and prohibited URL metadata.
- Outputs `data_quality_percentage = (valid / total) * 100`.

---

## 8. Defensive Recommendation Engine: 20-Rule Specification

Implemented in [src/recommendation_rules.py](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/recommendation_rules.py) and coordinated by [src/threat_recommendations.py](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/threat_recommendations.py).

Every rule inspects empirical evidence, compares metrics against configurable thresholds in `src/recommendation_config.py`, and assigns an actionable status: `active`, `insufficient_evidence`, `not_triggered`, or `unavailable`.

| Rule ID | Title | Target Category | Primary Trigger Condition | Default Threshold |
|---|---|---|---|---|
| **RULE_01** | Shortened URL protection | Email & web security | `Shortining_Service == -1` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 5.0\%$ |
| **RULE_02** | IP-address link defense | Email & web security | `having_IP_Address == -1` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 5.0\%$ |
| **RULE_03** | Lookalike & hyphenated domain defense | Domain & DNS | `Prefix_Suffix == -1` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 20.0\%$ |
| **RULE_04** | Subdomain & DNS hierarchy review | Domain & DNS | `having_Sub_Domain == -1` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 10.0\%$ |
| **RULE_05** | HTTPS & TLS certificate validation | Network & transport | `SSLfinal_State in {-1, 0}` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 15.0\%$ |
| **RULE_06** | URL normalization & redirect defense | Web gateway | `double_slash == -1` or `Redirect in {0, -1}` | $\text{Count} \ge 10, \text{Pct} \ge 5.0\%$ |
| **RULE_07** | External link & embedded media inspection | Content & HTML | `Request_URL in {0, -1}` or `Links_in_tags in {0, -1}` | $\text{Count} \ge 10, \text{Pct} \ge 15.0\%$ |
| **RULE_08** | Attachment & anchor destination defense | Email & content | `URL_of_Anchor in {0, -1}` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 15.0\%$ |
| **RULE_09** | Sender authentication & mailto defense | Email security | `Submitting_to_email == -1` count & percentage | $\text{Count} \ge 5, \text{Pct} \ge 2.0\%$ |
| **RULE_10** | Domain reputation & suspicious TLD review | Perimeter security | Top signals include domain/network anomalies | Co-occurrence $\ge 5\%$ |
| **RULE_11** | Outbound web access & non-standard ports | Network firewall | `port == -1` count & percentage | $\text{Count} \ge 10, \text{Pct} \ge 5.0\%$ |
| **RULE_12** | Security awareness training focus | Human security | Evaluates top 3 threat signals prevalence | Aggregate support $\ge 30.0\%$ |
| **RULE_13** | Lookalike domain monitoring & brand abuse | Threat intelligence | `Prefix_Suffix == -1` and `having_Sub_Domain == -1` | Joint support $\ge 10.0\%$ |
| **RULE_14** | Safe detonation & sandbox inspection | Endpoint & gateway | Prevalence of hidden/opaque structural tactics | Triggered if $\ge 2$ obfuscations active |
| **RULE_15** | Secure Web Gateway policy review | Web gateway | Broad-spectrum review of gateway-filterable signals | $\ge 3$ gateway signals exceed thresholds |
| **RULE_16** | Cluster-driven detection rules | Detection engineering | Largest cluster concentration and silhouette | Cluster size $\ge 20.0\%$, silhouette $\ge 0.15$ |
| **RULE_17** | Threat hunting for unusual patterns | Threat hunting | Rare patterns detected in population | Rare pattern count $\ge 1$ |
| **RULE_18** | Layered multi-channel defenses | Defensive posture | Multi-category trigger concurrence | Rules active across $\ge 3$ distinct categories |
| **RULE_19** | Control effectiveness review | Security metrics | High concentration in specific defensive control | Single category accounts for $\ge 40\%$ active |
| **RULE_20** | Prioritize strongest measured evidence | Strategic roadmap | Identifies rule with highest empirical support | Selected dynamically from top active rule |

---

## 9. Streamlit UI Dashboard: Component-by-Component Mapping

The dashboard is implemented in [app.py](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/app.py).

### 9.1. View 1: URL Input
- **Components**: Header, description of dual pipelines, URL input box, "Predict URL" button.
- **Backend Flow**:
  - `validate_url_format(user_url)` checks syntax.
  - `route_url(user_url, update_threat_intel=True)` executes the pipeline.
  - Updates `st.session_state["prediction_result"]` and navigates to View 2.

### 9.2. View 2: Prediction Result
- **Banner**: Displays `PHISHING` (red) or `LEGITIMATE` (green).
- **Metric Cards**:
  - *Predicted Label*: `res.predicted_label` (`-1` or `1`) and `res.label_description`.
  - *Phishing Probability*: `res.phishing_probability * 100` (e.g. `93.10%`).
  - *Pipeline Selected*: `res.pipeline` (`"20-feature"` or `"10-feature"`).
  - *Feature Vector Count*: `res.feature_count` ($20$ or $10$).
- **Routing & Inspection Context**: Status code, Content-Type, final resolved URL, and routing reason.
- **Extracted Feature Vector Table**: Expandable dataframe with actual feature column headers matching `FEATURES_10` or `FEATURES_20`.
- **Threat Intelligence Notice**: If phishing, indicates whether vector was stored into ChromaDB and whether clusters were refreshed.

### 9.3. View 3: Threat Activity Dashboard
- **Collection Radio Selector**: Toggles between `10_features` and `20_features`.
- **1. Overview Metrics**:
  - `Total Stored Cases`: ChromaDB `col.count()`.
  - `Distinct Vectors`: Deduplicated unique vector count from `summary.json`.
  - `Total Clusters`: $k$ from `clustering.json`.
  - `Active Recommendations`: Count of active rules from `recommendations.json`.
  - `Newly Triggered`: Count of newly triggered rules from state diff.
- **2. Feature Analytics & Signal Prevalence**:
  - *Value Distribution Chart*: Bar chart plotting percentages for $-1$, $0$, and $1$.
  - *Complete Statistics Table*: Tabular breakdown of counts and percentages per feature.
  - *Top Threat Signals*: Table of top 10 ranked threat signal conditions from `top_signals.json`.
- **3. Cluster Analysis & Archetypes**:
  - Displays algorithm (`KMeans`), distance metric (`euclidean`), and silhouette score.
  - Displays cluster membership table and distribution bar chart.
  - *Detailed Cluster Feature Profiles*: Centroids, dominant values, and uniformity per cluster.
  - *Rare Pattern Analysis*: Count of rare vectors ($\le 2$ instances) and JSON samples.
- **4. Defensive Recommendations & Evidence Summaries**:
  - Shows cards for each active recommendation with priority badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and `🔥 [NEWLY TRIGGERED]` indicator.
  - Displays business recommendation text, trigger rationale, JSON evidence, evaluation thresholds, and observational limitations.
- **5. Data Quality & Audit Integrity**:
  - Displays Data Quality Score percentage, Valid Records, and Invalid Records.

### 9.4. How to Trace Any Dashboard Metric to Source Code
To trace any number displayed in the dashboard back to its origin:
1. Locate the UI display block in `app.py` under `render_analysis_dashboard_view()`.
2. Observe the dictionary key accessed (e.g., `evidence_bundle.get("top_signals")`).
3. Follow `load_analytics_evidence()` in `src/threat_recommendations.py` to identify the JSON report loaded (e.g., `reports/threat_analytics/<collection>/top_signals.json`).
4. Look up the generating function in `src/threat_analytics.py` (e.g. `compute_top_signals()`).
5. Inspect the raw vector retrieval in `src/threat_vector_db.py` (`get_collection().get()`) from `chroma_db/chroma.sqlite3`.

---

## 10. File-by-File Implementation Map

| File Path | Primary Responsibility | Key Classes / Functions | Called By |
|---|---|---|---|
| `app.py` | Streamlit user interface (Input, Result, Dashboard) | `render_url_input_view`, `render_prediction_result_view`, `render_analysis_dashboard_view` | User execution (`streamlit run app.py`) |
| `src/ui_validator.py` | Lightweight frontend URL format validation | `validate_url_format(raw_input)` | `app.py` |
| `src/pipeline_router.py` | HTTP resource inspection, SSRF policy, pipeline selection | `route_url`, `check_url_resource`, `_is_safe_url_destination` | `app.py`, test suite |
| `src/classifier.py` | Random forest model loading, caching, and inference | `load_model`, `load_10_feature_model`, `predict_url`, `predict_url_10` | `pipeline_router.py`, test suite |
| `src/feature_extractor.py` | Live feature extraction for all 20 features | `extract_features`, `extract_10_features`, `extract_ssl_final_state`, `extract_port`, `fetch_webpage` | `classifier.py`, `pipeline_router.py` |
| `src/feature_contract.py` | Authoritative 10 & 20 feature order and allowed value sets | `validate_feature_vector`, `validate_10_feature_vector`, `FEATURE_NAMES`, `FEATURE_NAMES_10` | `feature_extractor.py`, `classifier.py` |
| `src/threat_vector_db.py` | ChromaDB persistence, collection initialization, vector validation | `get_chroma_client`, `get_collection`, `insert_phishing_vector`, `validate_vector` | `scripts/initialize_threat_vector_db.py`, `threat_integration_service.py` |
| `src/threat_analytics.py` | Pattern mining, statistical summaries, co-occurrence | `compute_total_cases`, `compute_feature_statistics`, `compute_top_signals`, `detect_unusual_patterns` | `threat_integration_service.py` |
| `src/threat_clustering.py` | Unsupervised KMeans clustering & cluster archetyping | `discover_clusters`, `analyze_cluster_sizes`, `profile_clusters` | `threat_analytics.py` |
| `src/threat_data_quality.py` | Read-only database auditing & anomaly detection | `audit_collection_data_quality`, `validate_single_record` | `threat_analytics.py` |
| `src/recommendation_config.py` | Configurable thresholds for recommendation rules | `RecommendationConfig`, `DEFAULT_RECOMMENDATION_CONFIG` | `threat_recommendations.py`, `recommendation_rules.py` |
| `src/recommendation_rules.py` | 20 transparent defensive rule definitions | `evaluate_rule_1_...` through `evaluate_rule_20_...`, `ALL_RULES` | `threat_recommendations.py` |
| `src/threat_recommendations.py` | Evidence bundle validation and recommendation generation | `load_analytics_evidence`, `evaluate_all_rules`, `generate_recommendation_report` | `threat_integration_service.py`, `app.py` |
| `src/threat_integration_service.py` | Decoupled prediction ingestion & state transition tracking | `process_prediction_result`, `compute_recommendation_diff`, `get_current_recommendation_state` | `pipeline_router.py`, `app.py` |
| `scripts/initialize_threat_vector_db.py` | CLI initialization script populating ChromaDB from CSV | `main`, `populate_collection` | Initial setup command |
| `train.py` | Retraining script for 20-feature model | `train_and_evaluate` | Model training CLI |
| `train_10_features.py` | Retraining script for 10-feature model | `train_10_feature_model` | Model training CLI |

---

## 11. Known Observations & Technical Limitations

1. **The `Prefix_Suffix` Dataset Property**:
   - In `data/phishing_20_features.csv` and `data/phishing_10_features.csv`, **all 4,898 phishing records have `Prefix_Suffix == -1`** (a hyphen is present in the domain).
   - Across the 11,055 samples, **zero** phishing records have `Prefix_Suffix == 1`.
   - As a consequence, decision trees learn that `Prefix_Suffix == 1` strongly correlates with legitimate domains in this specific training set. This is a characteristic of the training corpus rather than an architectural bug.
2. **Client-Side HTML Limitations**:
   - Client-side static scanners cannot detect server-side mail handling (e.g. PHP `mail()`) unless client code exposes form actions or JavaScript submission triggers.
3. **Network Feature Fallbacks**:
   - If an HTTPS connection times out or the host is down, `SSLfinal_State` falls back conservatively to `-1` (suspicious/unverified) rather than guessing legitimacy.
4. **No Raw URL Storage**:
   - The threat intelligence database deliberately avoids storing raw URLs to preserve user privacy and prevent data leakage of sensitive intranet URLs.
