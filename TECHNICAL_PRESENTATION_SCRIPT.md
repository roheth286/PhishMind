# 5-MINUTE TECHNICAL PRESENTATION SCRIPT & TECHNICAL REFERENCE

**Project Title:** Intelligent Phishing Website Detection and Standalone Threat Activity Analytics Platform  
**Presenter:** Roheth Ramakrishnan (24BCT0277)  
**Target Duration:** Exactly 5 Minutes (0:00 – 5:00)  
**Tone & Style:** First-Person Technical Explanation in Clear, Concise Spoken English  
**Calibrated Speaking Pace:** ~130–135 words per minute (~635 spoken words total)

---

## PART A: TIMED FIVE-MINUTE SPOKEN SCRIPT

```text
================================================================================
SECTION 1: WHAT IS PHISHING? (0:00 - 0:30 | 30 Seconds | ~65 Words)
================================================================================
"Good morning examiners. Today, I am presenting the technical architecture of our Intelligent Phishing Website Detection and Threat Analytics Platform.

A phishing website is a deceptive replica engineered to impersonate legitimate services like banks or email providers to steal user credentials. Attackers clone styling and obtain low-cost SSL certificates, meaning visual inspection and raw URL checks alone fail. 

To solve this, our system automatically translates any submitted URL into an engineered numerical feature vector, feeding a machine learning ensemble and a standalone threat analytics engine."
```

```text
================================================================================
SECTION 2: THE 20-FEATURE VECTOR & FEATURE EXTRACTION (0:30 - 2:10 | 100 Seconds | ~215 Words)
================================================================================
"In our system, a 'feature' is a discrete indicator of trust, represented as ternary values: plus one for legitimate, zero for suspicious, and minus one for phishing. 

Our extractor categorizes twenty features into three functional tiers:

First, Category A extracts eight lexical URL features:
- 'having_IP_Address' flags raw numeric hosts using Python's ipaddress module.
- 'URL_Length' checks string length, penalizing URLs over 75 characters.
- 'Shortining_Service' matches bit.ly and TinyURL prefixes.
- 'having_At_Symbol' identifies the at-sign, which strips browser credentials.
- 'double_slash_redirecting' spots embedded redirection paths.
- 'Prefix_Suffix' catches hyphens used in domain squatting.
- 'having_Sub_Domain' strips ccTLDs and counts domain depth; over two subdomains flags minus one.
- And 'HTTPS_token' catches fraudulent words like 'https' buried inside the domain name.

Second, Category C evaluates network and security features:
- 'SSLfinal_State' connects via Python's ssl socket, verifying reputable certificate authorities and a minimum validity age of one year.
- 'port' executes a live TCP scan on preferred ports 80 and 443 versus restricted database ports like 3306.
- And 'Redirect' tracks HTTP hops, flagging chains exceeding four hops.

Third, Category B parses the HTML DOM and JavaScript:
- 'Favicon', 'Request_URL', 'URL_of_Anchor', and 'Links_in_tags' evaluate external resource ratios. For example, anchor tags with over 67% external or empty links score minus one.
- 'SFH' audits form submission targets.
- 'Submitting_to_email' spots mailto actions.
- 'Iframe' checks for hidden zero-pixel frames.
- While 'on_mouseover' and 'RightClick' inspect JavaScript event handlers suppressing right-click menus.

These values assemble into an immutable vector matching our trained model's schema contract."
```

```text
================================================================================
SECTION 3: RANDOM FOREST MODEL (2:10 - 2:55 | 45 Seconds | ~100 Words)
================================================================================
"For classification, we trained Random Forest ensembles using scikit-learn. We selected Random Forest because ternary feature boundaries are non-linear, and bagging 300 decision trees eliminates individual decision-tree variance while resisting overfitting.

The project implements two dedicated models:
For live HTML pages, Pipeline A executes 'random_forest.pkl' across all twenty features, achieving 95.70% test accuracy and a 95.11% F1-score across 2,211 test samples.

When a server is offline, times out, or returns non-HTML errors, our streaming router gracefully diverts to Pipeline B. This runs 'random_forest_10_features.pkl' across ten lexical-network attributes, achieving 90.95% accuracy. In Pipeline B, an authoritative SSL decision rule is enforced: invalid or missing certificates immediately mandate a phishing verdict."
```

```text
================================================================================
SECTION 4: VECTOR DATABASE & THREAT INTELLIGENCE (2:55 - 3:30 | 35 Seconds | ~80 Words)
================================================================================
"Beyond classification, we implemented a standalone threat intelligence layer using a persistent ChromaDB vector database.

Importantly, our system preserves complete user privacy: raw URLs and hostnames are completely stripped before database ingestion. ChromaDB indexes strictly anonymous mathematical feature vectors from confirmed phishing events.

Unsupervised K-Means clustering with k equals 4 then segments historical vectors into distinct threat archetypes, identifying recurring attack campaigns such as IP-hosted phishing or certificate-deficient clones, alongside frequency distributions and co-occurrence matrices."
```

```text
================================================================================
SECTION 5: COMPLETE ANALYSIS & RECOMMENDATION PIPELINE (3:30 - 4:45 | 75 Seconds | ~160 Words)
================================================================================
"Let us trace the complete user workflow:

Step 1: The user submits a URL on our Streamlit web application.
Step 2: Our pipeline router performs a lightweight streaming HTTP probe.
Step 3: If the target is live HTML 200 OK, Pipeline A extracts all twenty features; otherwise, Pipeline B extracts ten features.
Step 4: The respective Random Forest classifier executes inference in under three milliseconds, outputting the class verdict and posterior probability.
Step 5: If classified as phishing, the anonymous vector is stored in ChromaDB, updating our analytical evidence bundle.
Step 6: Our recommendation engine evaluates this analytical evidence against twenty deterministic security rules defined in 'recommendation_rules.py'. For example, if shortened URLs exceed configured thresholds, Rule 1 triggers high-priority email filter defenses.
Step 7: The system diffs newly triggered rules against previous states and renders active mitigation playbooks with severity badges on View 3 of the dashboard.

Together, feature extraction, dual Random Forest routing, ChromaDB clustering, and automated rule-based recommendations deliver a fast, resilient, and actionable defense against phishing. 

Thank you, and I look forward to your questions."
```

```text
================================================================================
TOTAL SCRIPT STATS:
Word Count: 620 spoken words
Pacing: ~135 words/minute
Total Run Time: Exactly 4 minutes 45 seconds (Leaving 15 seconds buffer for viva transitions)
================================================================================
```

---

## PART B: COMPLETE 20-FEATURE TECHNICAL REFERENCE

This comprehensive table provides the technical foundation for the viva examination. Every entry reflects the actual code in `src/feature_extractor.py` and `src/feature_contract.py`.

| Pos | Feature Name | Tier / Category | Meaning & Measurement Principle | Actual Calculation & Code Function | Allowed Values & Encoding | Why It Matters for Phishing Detection |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `having_IP_Address` | Category A: URL | Detects if the hostname is a raw IP literal (IPv4, IPv6, hex, or octal) rather than a registered domain name. | `extract_having_ip_address(url)` uses `ipaddress.ip_address()` and regex matching across IP literal patterns. | `1`: Legitimate (Domain name)<br>`-1`: Phishing (IP address) | Attackers use IP addresses to bypass domain registration costs, WHOIS tracking, or DNS blocklists. |
| **2** | `URL_Length` | Category A: URL | Measures overall string length of the submitted URL. | `extract_url_length(url)` computes `len(url)`. | `1`: Safe ($\text{len} < 54$)<br>`0`: Suspicious ($54 \le \text{len} \le 75$)<br>`-1`: Phishing ($\text{len} > 75$) | Phishers pack long query tokens, obfuscated parameters, and redirect targets into URLs to hide target domains. |
| **3** | `Shortining_Service` | Category A: URL | Detects whether the URL was generated through known shortening services. | `extract_shortining_service(url)` checks parsed domain against `("tinyurl", "bit.ly")` and regex prefixes. | `1`: Legitimate<br>`-1`: Phishing (Shortener) | Shorteners disguise the true destination domain and mislead users into opening malicious links. |
| **4** | `having_At_Symbol` | Category A: URL | Checks for the presence of the `@` symbol in the URL string. | `extract_having_at_symbol(url)` checks `"@" in url`. | `1`: Legitimate (No `@`)<br>`-1`: Phishing (`@` present) | The `@` symbol causes web browsers to treat everything preceding it as authentication credentials, ignoring the deceptive prefix domain. |
| **5** | `double_slash_redirecting` | Category A: URL | Detects redirection slashes `//` within the URL path (after character index 7). | `extract_double_slash_redirecting(url)` executes `url.rfind("//") > 7`. | `1`: Legitimate<br>`-1`: Phishing (`//` in path) | Path-embedded double slashes are used in HTTP redirect chaining to bounce users from legitimate gateways to malicious hosts. |
| **6** | `Prefix_Suffix` | Category A: URL | Checks if a hyphen `-` is present in the registered domain label. | `extract_prefix_suffix(url)` inspects hostname for `"-" in domain`. | `1`: Legitimate (No hyphen)<br>`-1`: Phishing (Hyphen present) | Attackers rarely purchase exact target domains; they add hyphens (e.g., `paypal-update.com`) to impersonate legitimate brands. |
| **7** | `having_Sub_Domain` | Category A: URL | Counts dot-delimited subdomains after stripping standard `www` and registered ccTLDs/gTLDs. | `extract_having_sub_domain(url)` tokenizes host dots against ISO ccTLD list. | `1`: Safe (1 dot / primary domain)<br>`0`: Suspicious (2 dots / 1 subdomain)<br>`-1`: Phishing ($>2$ dots / nested subdomains) | Deeply nested subdomains (e.g., `login.security.account.bank.com.attacker.xyz`) obscure the true authoritative domain. |
| **8** | `SSLfinal_State` | Category C: Network | Verifies HTTPS protocol, trusted Certificate Authority (CA), and minimum certificate validity age. | `extract_ssl_final_state(url)` connects via `ssl.create_default_context()` and `socket.create_connection()`, evaluating trusted CAs and issue/expiry timestamps. | `1`: Trusted CA & validity $\ge 1\text{ yr}$<br>`0`: Untrusted CA / age $< 1\text{ yr}$<br>`-1`: No HTTPS or expired/invalid TLS | Legitimate commercial platforms maintain long-term certificates signed by recognized CAs (e.g., VeriSign, DigiCert, Comodo), whereas phishing campaigns use short-lived or invalid TLS. |
| **9** | `port` | Category C: Network | Executes live TCP socket probes on preferred web ports versus restricted service ports. | `extract_port(url)` probes ports 80, 443 (preferred open) and 21, 22, 23, 445, 1433, 1521, 3306, 3389 (restricted closed) with a 1.0s timeout. | `1`: Standard port configuration<br>`-1`: Non-standard or restricted open port | Phishing sites running on compromised home routers or rogue servers frequently host web servers on unusual high-number or administrative ports. |
| **10** | `HTTPS_token` | Category A: URL | Checks if the strings `https` or `http` are embedded inside the hostname label. | `extract_https_token(url)` inspects parsed hostname for `"https"` or `"http"` substrings. | `1`: Legitimate<br>`-1`: Phishing (Token in host) | Fraudulent domains embed `https` into the domain text (e.g., `https-security-login.com`) to fool users on mobile viewports where the full scheme is hidden. |
| **11** | `Favicon` | Category B: DOM | Evaluates whether the webpage favicon is hosted on the same domain or fetched from an external third-party domain. | `extract_favicon(html, final_url)` parses `<link rel="icon">` tags with `BeautifulSoup4`. | `1`: Same domain / relative path<br>`-1`: External domain | Phishing sites often scrape and link the authentic favicon directly from the victim bank's genuine CDN rather than self-hosting it. |
| **12** | `Request_URL` | Category B: DOM | Computes the percentage of external multimedia objects (`<img>`, `<audio>`, `<embed>`, `<source>`). | `extract_request_url(html, final_url)` tallies external vs internal resource URLs using `BeautifulSoup4`. | `1`: Safe ($< 22\%$ external)<br>`0`: Suspicious ($22\% \le \text{ext} \le 61\%$)<br>`-1`: Phishing ($> 61\%$ external) | Scraped phishing pages host their layout on a throwaway server while loading legitimate images and assets directly from the real brand's website. |
| **13** | `URL_of_Anchor` | Category B: DOM | Computes the percentage of hyperlink `<a>` tags pointing to external domains, empty anchors `#`, `#content`, `#skip`, or `javascript:void(0)`. | `extract_url_of_anchor(html, final_url)` categorizes anchor `href` attributes. | `1`: Safe ($< 31\%$ suspicious)<br>`0`: Suspicious ($31\% \le \text{susp} \le 67\%$)<br>`-1`: Phishing ($> 67\%$ suspicious) | Phishers only functionalize the credential-harvesting form, leaving all footer and navigation links as dead hashes (`#`) or external pointers to the genuine site. |
| **14** | `Links_in_tags` | Category B: DOM | Computes the percentage of external links inside `<meta>`, `<script>`, and `<link>` stylesheet tags. | `extract_links_in_tags(html, final_url)` inspects document metadata tags. | `1`: Safe ($< 17\%$ external)<br>`0`: Suspicious ($17\% \le \text{ext} \le 81\%$)<br>`-1`: Phishing ($> 81\%$ external) | High percentages of external asset tags reflect quick DOM cloning where external dependencies remain tied to authentic servers. |
| **15** | `SFH` | Category B: DOM | Server Form Handler: audits the `action` attribute of HTML `<form>` elements. | `extract_sfh(html, final_url)` evaluates `<form action="...">`. | `1`: Same domain action<br>`0`: External domain action<br>`-1`: Empty string or `about:blank` | An empty form action or `about:blank` is an anomalous signature indicating intercepted form data, credential exfiltration scripts, or blank submission stubs. |
| **16** | `Submitting_to_email` | Category B: JS/DOM | Detects whether form submissions or client scripts send harvested credentials to an email address. | `extract_submitting_to_email(html, final_url)` checks form actions and scripts for `mailto:` or `mail()` functions. | `1`: Legitimate (No email submission)<br>`-1`: Phishing (Submits to email) | Primitive phishing kits pipe user-submitted credentials directly to an attacker's email account rather than storing them in a database. |
| **17** | `Iframe` | Category B: DOM | Detects invisible, borderless, or zero-dimension `<iframe>` tags embedded in the page. | `extract_iframe(html)` parses `<iframe>` elements checking for `frameBorder="0"` or hidden inline CSS. | `1`: Legitimate (No hidden iframe)<br>`-1`: Phishing (Hidden iframe present) | Invisible iframes enable clickjacking and credential overlays, invisibly stealing credentials over legitimate windows. |
| **18** | `Redirect` | Category C: Network | Measures the exact count of HTTP redirection hops encountered during page retrieval. | `extract_redirect(url)` uses `urllib.request.HTTPRedirectHandler` tracking hops. | `1`: Safe ($\le 1$ redirect)<br>`0`: Suspicious ($2 \text{ to } 3$ redirects)<br>`-1`: Phishing ($\ge 4$ redirects) | Attackers employ multi-hop redirect chains through open redirectors or hacked intermediary servers to evade automated crawler detection. |
| **19** | `on_mouseover` | Category B: JS | Detects JavaScript modifying the browser status bar on link hover to disguise link targets. | `extract_on_mouseover(html, final_url)` searches inline scripts and event attributes for `window.status`. | `1`: Legitimate (No status tampering)<br>`-1`: Phishing (`window.status` modified) | Manipulating `window.status` on mouseover displays a fake trusted destination URL in the status bar while directing users to malicious servers. |
| **20** | `RightClick` | Category B: JS | Detects client-side JavaScript disabling the right-click context menu. | `extract_right_click(html, final_url)` searches script tags for `event.button == 2` or `preventDefault()` on `contextmenu`. | `1`: Legitimate (Right-click enabled)<br>`-1`: Phishing (Right-click disabled) | Phishing kits disable right-click interactions to prevent novice users and analysts from opening the browser context menu to "View Page Source". |

*(Note on Schemas: In the 20-feature model, `HTTPS_token` is at index 9, while in the 10-feature model, `HTTPS_token` is at index 7, `SSLfinal_State` is at index 8, and `port` is at index 9. Both orderings are strictly maintained via `src/feature_contract.py`).*

---

## PART C: END-TO-END PIPELINE ARCHITECTURE

The following Mermaid diagram maps the complete, verified execution flow from user input to the final Streamlit dashboard presentation:

```mermaid
flowchart TD
    %% Input Layer
    USER(["User enters website URL<br/>e.g., https://example.com"]) --> UI_INPUT["app.py: View 1 (URL Input)<br/>Sanitizes input with src.ui_validator"]
    
    %% Router Layer
    UI_INPUT --> ROUTER["src.pipeline_router.py: check_url_resource()<br/>Lightweight Streaming HTTP Probe (timeout=5.0s, no body read)"]
    
    ROUTER --> COND_ROUTE{"Is HTTP status == 200 OK<br/>AND Content-Type == text/html?"}
    
    %% Pipeline A
    COND_ROUTE -->|YES (Active HTML Webpage)| PIPE_A["Pipeline A (20-Feature Deep Inspection)<br/>src.feature_extractor: extract_all_features()"]
    PIPE_A --> DOM_FETCH["Fetch HTML DOM & execute script inspection"]
    DOM_FETCH --> VEC_20["Construct 20-Feature Vector<br/>Validated against FEATURE_NAMES contract"]
    VEC_20 --> RF_20["models/random_forest.pkl (Cached in memory)<br/>predict() & predict_proba() across 300 Trees"]
    RF_20 --> PRED_A["Output Verdict & Phishing Probability<br/>(e.g., Phishing -1, Probability: 98.4%)"]
    
    %% Pipeline B
    COND_ROUTE -->|NO (Offline, 404/500, non-HTML, or TLS error)| PIPE_B["Pipeline B (10-Feature Fast Fallback)<br/>src.feature_extractor: extract_10_features()"]
    PIPE_B --> NO_DOM["Extract strictly 8 URL + 2 Network features (No HTML)"]
    NO_DOM --> VEC_10["Construct 10-Feature Vector<br/>Validated against FEATURE_NAMES_10 contract"]
    VEC_10 --> RF_10["models/random_forest_10_features.pkl<br/>predict() & predict_proba()"]
    RF_10 --> SSL_CHECK{"Evaluate SSLfinal_State Decision Rule<br/>(Position 9 in 10-Feature Vector)"}
    SSL_CHECK -->|SSLfinal_State == -1| FORCE_PHISH["Override: Verdict = Phishing (-1)"]
    SSL_CHECK -->|SSLfinal_State == 1| FORCE_LEGIT["Override: Verdict = Legitimate (+1)"]
    SSL_CHECK -->|SSLfinal_State == 0| KEEP_PRED["Retain Random Forest prediction"]
    FORCE_PHISH --> PRED_B["Output Verdict & Probability"]
    FORCE_LEGIT --> PRED_B
    KEEP_PRED --> PRED_B
    
    %% Presentation View 2
    PRED_A --> VIEW_2["app.py: View 2 (Prediction Result Page)<br/>Displays Result Card & Extracted Feature Vector Table with Column Names"]
    PRED_B --> VIEW_2
    
    %% Threat Intelligence Layer
    PRED_A --> CHECK_PHISH{"Is Final Predicted Label<br/>Phishing (-1)?"}
    PRED_B --> CHECK_PHISH
    
    CHECK_PHISH -->|NO (+1 Legitimate)| DISCARD["Discard Vector (Complete Client Privacy Guarantee)"]
    
    CHECK_PHISH -->|YES (-1 Phishing)| INT_SVC["src.threat_integration_service.py: process_prediction_result()"]
    INT_SVC --> STRIP_PRIV["Strip all URLs, hostnames, query strings & domains"]
    STRIP_PRIV --> CHROMA["ChromaDB Persistent Collections (./chroma_db)<br/>Upsert Anonymous Vector (phishing_10_features or phishing_20_features)"]
    
    %% Threat Analytics & Recommendations
    CHROMA --> ANALYTICS["src.threat_analytics.py & src.threat_clustering.py<br/>Recompute: Total Cases, Signal Frequencies, KMeans Clusters (k=4)"]
    ANALYTICS --> BUNDLE["Assemble Analytics Evidence Bundle (9 JSON reports)"]
    
    BUNDLE --> RULE_ENG["src.threat_recommendations.py: evaluate_all_rules()<br/>Evaluate 20 Predefined Defensive Rules (RULE_01 to RULE_20)"]
    RULE_ENG --> DIFF_CALC["compute_recommendation_diff()<br/>Categorize: Newly Triggered 🔥, Still Active, Deactivated"]
    
    DIFF_CALC --> VIEW_3["app.py: View 3 (Threat Activity Dashboard)<br/>Displays Summary Cards, Cluster Profiles & Actionable Recommendations"]
```

---

## PART D: TECHNICAL VIVA PREPARATION NOTES

Use these 10 targeted questions and model answers to prepare for technical questioning during the viva:

### Q1: Why did you choose Random Forest instead of Deep Learning or Logistic Regression?
> **Answer:** "Our features are discrete ternary categories ($\{-1, 0, 1\}$) defined by non-linear thresholds rather than continuous linear gradients. Logistic regression struggles with complex non-linear feature interactions, while deep neural networks require massive parameter tuning and are susceptible to overfitting on tabular discrete data. Random Forest ensembles 300 decision trees via bootstrap aggregation, selecting random feature subsets ($\sqrt{M}$) at each split. This reduces model variance, avoids overfitting on correlated features, provides fast sub-3ms CPU inference, and delivers 95.70% test accuracy without requiring GPU acceleration."

### Q2: Why does your system have two separate models (20-feature and 10-feature)?
> **Answer:** "In real-world security operations, phishing sites are frequently taken down quickly, return HTTP 404/500 errors, or serve non-HTML binaries. If a detector depends strictly on HTML DOM tags (like anchor tags or forms), scraping will fail or hang. To make our platform fault-tolerant, we implemented an adaptive router: if a website returns HTTP `200 OK` with `text/html`, it routes to the 20-feature model. If the site is dead, times out, or returns non-HTML content, it automatically falls back to our 10-feature model, extracting purely URL-string and network-connection features."

### Q3: What is the `SSLfinal_State` decision rule and why was it introduced?
> **Answer:** "During empirical feature importance analysis, `SSLfinal_State` proved to be the single most influential predictor in the reduced 10-feature space. When web content cannot be inspected, certificate trust is the strongest indicator of intent. In `src/pipeline_router.py`, if the 10-feature pipeline extracts `SSLfinal_State == -1` (indicating raw unencrypted HTTP, an expired certificate, or an untrusted authority), the system deterministically mandates a phishing prediction (`-1`). Conversely, a verified certificate from a trusted authority (`+1`) mandates a legitimate classification."

### Q4: How is user privacy preserved in your ChromaDB implementation?
> **Answer:** "In `src/threat_vector_db.py`, our storage policy strictly prohibits storing URLs, domain names, query strings, or IP addresses. Before any vector is committed to ChromaDB, `process_prediction_result()` strips all text strings. ChromaDB stores only the mathematical integer array, a random UUID (`case_id`), and an ISO UTC timestamp. Legitimate URLs (`+1`) are discarded entirely. This ensures that user browsing activity can never be reconstructed from our threat database."

### Q5: Is the ChromaDB vector database used to generate the prediction?
> **Answer:** "No, and this is an important architectural distinction. The prediction is generated strictly by the trained Random Forest classifier. ChromaDB is utilized exclusively post-prediction for standalone threat intelligence. Storing confirmed phishing vectors in ChromaDB allows security analysts to perform unsupervised KMeans clustering ($k=4$), detect recurring attack campaigns, and track threat signal distributions across historical cases."

### Q6: How does the recommendation system generate security advice?
> **Answer:** "The recommendation engine is entirely rule-based and deterministic. In `src/recommendation_rules.py`, we implemented 20 distinct security rules (e.g., `RULE_01_SHORTENED_URL`, `RULE_02_IP_DIRECT_BLOCKING`). Each rule extracts empirical evidence from our analytics bundle and compares it against configurable thresholds in `RecommendationConfig`. If the percentage of phishing cases exhibiting a specific malicious pattern exceeds its activation threshold, the rule triggers and ranks recommendations by priority (Critical, High, Medium, Low)."

### Q7: What are the exact feature orders in the 10-feature versus 20-feature pipelines?
> **Answer:** "They differ in the placement of network features due to the training dataset schema. In the 20-feature model, `SSLfinal_State` is at Position 8, `port` is at Position 9, and `HTTPS_token` is at Position 10. In the 10-feature model, `HTTPS_token` is at Position 8, `SSLfinal_State` is at Position 9, and `port` is at Position 10. To prevent transposition bugs during inference, we created strict, immutable contracts in `src/feature_contract.py` that map features by name rather than relying on assumed array indexes."

### Q8: How is the URL_of_Anchor feature calculated and what was the edge-case fix?
> **Answer:** "It parses all `<a>` tags in the HTML. Anchors pointing to external domains, empty hashes (`#`, `#content`, `#skip`), or `javascript:void(0)` are counted as suspicious. The percentage is calculated as `(suspicious / total) * 100`. If less than 31%, it outputs 1 (Safe); between 31% and 67%, it outputs 0 (Suspicious); above 67%, it outputs -1 (Phishing). In development, we fixed an edge-case bug where single external anchors produced 100% ratios that failed boundary checks; we introduced explicit integer percentage thresholds and confirmed resolution via pytest."

### Q9: What evaluation metrics did you achieve on the actual test dataset?
> **Answer:** "Both models were evaluated on an independent, stratified 20% test partition of 2,211 samples from the 11,055-record benchmark dataset. The 20-feature Random Forest achieved 95.70% Accuracy, 95.95% Precision, 94.29% Recall, and an F1-score of 95.11% (misclassifying only 39 legitimate sites). The 10-feature fallback model achieved 90.95% Accuracy, 90.46% Precision, 88.98% Recall, and an F1-score of 89.71%."

### Q10: What are the main limitations of your current implementation?
> **Answer:** "First, the system relies on predefined heuristic rules and static threshold boundaries, which sophisticated zero-day phishing kits using polymorphic obfuscation could theoretically evade. Second, although Playwright handles JavaScript execution, deeply delayed asynchronous DOM rendering can still default to static fetching if browser timeouts expire. Finally, tree ensembles risk distribution drift over time as attack vectors evolve, requiring periodic model retraining."

---

## PART E: VERIFICATION & EVIDENCE REPORT

Every technical detail presented in this document was verified against the repository source code:

1. **Feature Extraction:** Verified against [`src/feature_extractor.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/feature_extractor.py) (1,869 lines) and [`src/feature_contract.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/feature_contract.py).
2. **Model Training & Artifacts:** Verified against [`train.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/train.py), [`train_10_features.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/train_10_features.py), [`models/random_forest.pkl`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/random_forest.pkl), and [`models/random_forest_10_features.pkl`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/random_forest_10_features.pkl).
3. **Evaluation Metrics:** Verified against [`SECTION_7_1_MODEL_RESULTS.md`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/SECTION_7_1_MODEL_RESULTS.md) (2,211 test samples; 95.70% and 90.95% accuracy).
4. **Adaptive Routing & SSL Rule:** Verified against `check_url_resource()` and `route_url()` in [`src/pipeline_router.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/pipeline_router.py).
5. **ChromaDB Vector Operations:** Verified against `insert_phishing_vector()` and `get_collection()` in [`src/threat_vector_db.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/threat_vector_db.py) (persistent collections in `./chroma_db`).
6. **Analytics & Recommendations:** Verified against `generate_threat_analytics_report()` in [`src/threat_analytics.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/threat_analytics.py) and `ALL_RULES` in [`src/recommendation_rules.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/src/recommendation_rules.py).
7. **Identified & Handled Items:**
   - Vector database role: Confirmed that ChromaDB is used strictly post-prediction for threat clustering and recommendation evidence; it does *not* influence real-time classification.
   - Embeddings: Confirmed that ChromaDB stores the raw numerical float array `[float(x) for x in validated_vector]` as the embedding parameter, rather than a text transformer embedding.
