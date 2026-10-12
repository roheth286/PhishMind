# Chapter 5: Methodology

---

## 5.2 Dataset and Preprocessing

The machine learning models developed in this project rely on a benchmark phishing dataset derived from the UCI Machine Learning Repository Phishing Websites dataset. To support the dual-pipeline architecture—accommodating both fully responsive web pages and unreachable or non-HTML resources—two dedicated dataset variants were curated and verified: a 20-feature dataset (`phishing_20_features.csv`) and a 10-feature dataset (`phishing_10_features.csv`), both stored within the `data/` directory.

### 5.2.1 Dataset Composition and Schema

Both datasets comprise exactly **11,055 records**, representing genuine and malicious URL instances. Each instance is labeled by a target variable named `Result`, encoded as a discrete binary class:
- **`-1` (Phishing)**: Represents confirmed phishing instances, totaling **4,898 records** (**44.31%** of the dataset).
- **`+1` (Legitimate)**: Represents verified legitimate instances, totaling **6,157 records** (**55.69%** of the dataset).

The dataset features capture structural, lexical, network, DOM, and behavioral characteristics of URLs:
1. **20-Feature Dataset (`data/phishing_20_features.csv`)**: Contains 20 input attributes covering lexical URL properties (`having_IP_Address`, `URL_Length`, `Shortining_Service`, `having_At_Symbol`, `double_slash_redirecting`, `Prefix_Suffix`, `having_Sub_Domain`), network configurations (`SSLfinal_State`, `port`, `HTTPS_token`), HTML DOM structures (`Favicon`, `Request_URL`, `URL_of_Anchor`, `Links_in_tags`, `SFH`, `Iframe`), and JavaScript behaviors (`Submitting_to_email`, `Redirect`, `on_mouseover`, `RightClick`), alongside the target column `Result` (21 total columns).
2. **10-Feature Dataset (`data/phishing_10_features.csv`)**: Derived directly from the primary dataset by selecting the 10 lightweight lexical and network features (`having_IP_Address`, `URL_Length`, `Shortining_Service`, `having_At_Symbol`, `double_slash_redirecting`, `Prefix_Suffix`, `having_Sub_Domain`, `HTTPS_token`, `SSLfinal_State`, `port`) alongside `Result` (11 total columns). This dataset trains the fallback model operating when webpage DOM inspection is impossible.

### 5.2.2 Data Preprocessing and Feature Encoding

In contrast to raw text or unnormalized continuous values, the attributes in both datasets are pre-discretized into ternary categorical states based on strict domain rules:
$$\{-1, 0, 1\} \iff \{\text{Phishing / Anomalous}, \text{Suspicious / Neutral}, \text{Legitimate / Safe}\}$$

Because the features already exist in this standardized ordinal and discrete format, extensive standard scaling (e.g., Min-Max normalization or Z-score standardization) or one-hot encoding was intentionally avoided:
- **Preservation of Ternary Semantics**: Applying continuous scaling would distort the discrete boundaries of domain-specific indicators (e.g., altering a discrete flag into a continuous fraction).
- **Prevention of Dimensionality Inflation**: One-hot encoding ternary features would triple feature dimensionality without adding informative variance, diluting tree splitting efficiency.
- **Scikit-Learn Preprocessing Pipeline**: A scikit-learn `ColumnTransformer` with `("passthrough", ...)` was implemented in both `train.py` and `train_10_features.py` to enforce the exact feature schema ordering and guarantee that during inference, feature vectors adhere strictly to the expected dimensional contracts.

### 5.2.3 Train-Test Partitioning

Both datasets were partitioned into training and testing subsets using an **80/20 stratified split** via scikit-learn's `train_test_split` with a fixed random seed (`random_state=42`):
- **Training Set (80%)**: **8,844 samples** (3,918 Phishing, 4,926 Legitimate).
- **Test Set (20%)**: **2,211 samples** (980 Phishing, 1,231 Legitimate).

Stratification ensured that the class balance (44.31% Phishing to 55.69% Legitimate) was strictly maintained across both subsets, avoiding class representation bias.

---

### Table 5.1: Dataset Summary

| Attribute / Parameter | 20-Feature Dataset (`phishing_20_features.csv`) | 10-Feature Dataset (`phishing_10_features.csv`) |
| :--- | :--- | :--- |
| **File Location** | `data/phishing_20_features.csv` | `data/phishing_10_features.csv` |
| **Total Sample Count** | 11,055 records | 11,055 records |
| **Input Feature Count** | 20 features | 10 features |
| **Target Column** | `Result` | `Result` |
| **Target Class Distribution** | Phishing (`-1`): 4,898 (44.31%)<br>Legitimate (`1`): 6,157 (55.69%) | Phishing (`-1`): 4,898 (44.31%)<br>Legitimate (`1`): 6,157 (55.69%) |
| **Feature Value Domain** | Ternary discrete $\{-1, 0, 1\}$ | Ternary discrete $\{-1, 0, 1\}$ |
| **Train / Test Split Ratio** | 80% Train / 20% Test (Stratified) | 80% Train / 20% Test (Stratified) |
| **Random State** | `42` | `42` |
| **Training Sample Count** | 8,844 records | 8,844 records |
| **Testing Sample Count** | 2,211 records | 2,211 records |
| **Preprocessing Method** | `ColumnTransformer` (Schema Passthrough) | `ColumnTransformer` (Schema Passthrough) |
| **Target Model Pipeline** | Pipeline A (Full Page Inspection) | Pipeline B (Reduced Network / Lexical) |

---

## 5.3 Model Training and Evaluation

### 5.3.1 Algorithm Selection Rationale: Random Forest Classifier

The **Random Forest** algorithm was selected as the core classification model for both pipelines due to several key advantages tailored to web threat detection:
1. **Resilience to Overfitting via Ensemble Bagging**: Random Forest constructs an ensemble of de-correlated decision trees ($B = 300$). By aggregating tree votes via bootstrap aggregation, the model reduces variance and dampens the noise inherent to live network measurements.
2. **Native Handling of Discrete Ternary Values**: Decision trees split directly on discrete integer categories ($\le -0.5, \le 0.5$) without requiring linear distance assumptions or synthetic numerical projections.
3. **Calibrated Class Probabilities**: Unlike hard-margin classifiers (such as standard Support Vector Machines), Random Forest yields reliable posterior probability estimates via `predict_proba()`, providing confidence levels and risk scores.
4. **Sub-Millisecond Inference Speed**: Once trained, tree traversal requires minimal CPU cycles ($< 5\text{ ms}$), ensuring that machine learning inference introduces negligible latency compared to live network I/O.
5. **Interpretability and Feature Importance**: Random Forest naturally computes Mean Decrease in Impurity (Gini importance) and permits permutation feature importance analysis, enabling ranking of security signals.

### 5.3.2 Model Training, Hyperparameters, and Serialization

Model training is orchestrated by two dedicated, reproducible Python scripts:
- `train.py`: Trains the 20-feature Random Forest model using `data/phishing_20_features.csv` and serializes the resulting classifier to `models/random_forest.pkl`.
- `train_10_features.py`: Trains the 10-feature Random Forest model using `data/phishing_10_features.csv` and serializes the classifier to `models/random_forest_10_features.pkl`.

Both models were trained using identical hyperparameter configurations to ensure comparability:
- `n_estimators = 300`: Ensures convergence of ensemble voting across diverse tree topologies.
- `random_state = 42`: Guarantees deterministic training results.
- `class_weight = "balanced"`: Adjusts tree splitting weights inversely proportional to class frequencies to counteract class imbalance.
- `max_features = "sqrt"`: Employs square-root feature subsets at each split to de-correlate individual trees.
- `n_jobs = -1`: Utilizes all available processor cores for parallel tree induction.

Model artifacts and preprocessors are serialized using `joblib`. In addition, feature schemas (`models/features_10_features.json`), importance scores (`models/feature_importance.csv`, `models/feature_importance_10_features.csv`), and confusion matrices are generated automatically.

### 5.3.3 Pipeline Selection and Hybrid Decision Logic

At runtime, `src/pipeline_router.py` probes the target URL and dynamically routes inference:
- **Pipeline A (Full 20-Feature Pipeline)**: Selected when an HTTP HEAD/GET probe confirms an active, reachable server returning an HTTP `200 OK` status with `text/html` content. All 20 features are extracted, and inference is executed using `models/random_forest.pkl`.
- **Pipeline B (Reduced 10-Feature Pipeline)**: Selected when the target server is unreachable, times out, returns HTTP errors (e.g., 404, 500), or serves non-HTML content (e.g., plain text or JavaScript). Only the 10 lexical and network features are extracted, and inference is executed using `models/random_forest_10_features.pkl`.
- **Primary Feature Decision Rule (Pipeline B)**: For Pipeline B, domain verification demonstrated that `SSLfinal_State` is the single most decisive security indicator. An authoritative decision rule is enforced at the router level:
  - If $\text{SSLfinal\_State} = -1 \implies \text{Prediction} = -1 \text{ (Phishing)}$
  - If $\text{SSLfinal\_State} = +1 \implies \text{Prediction} = +1 \text{ (Legitimate)}$

### 5.3.4 Empirical Evaluation Metrics

Both models were evaluated on the held-out test partition consisting of **2,211 unseen records** (980 Phishing, 1,231 Legitimate). With the positive class defined as **Phishing (`Result = -1`)**, the metrics were evaluated using standard classification formulations:
$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
$$\text{Precision} = \frac{TP}{TP + FP}$$
$$\text{Recall} = \frac{TP}{TP + FN}$$
$$\text{F1 Score} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

The actual verified metrics documented in `models/training_metrics.txt` and `models/training_metrics_10_features.txt` are as follows:

1. **20-Feature Random Forest Model (`random_forest.pkl`)**:
   - **Accuracy**: **95.7033%** (0.9570)
   - **Precision**: **95.9502%** (0.9595)
   - **Recall**: **94.2857%** (0.9429)
   - **F1 Score**: **95.1107%** (0.9511)
   - **Confusion Matrix** (True $\backslash$ Predicted on labels $[-1, 1]$):
     - **True Positives ($TP$, Phishing as Phishing)**: **924**
     - **False Negatives ($FN$, Phishing as Legitimate)**: **56**
     - **False Positives ($FP$, Legitimate as Phishing)**: **39**
     - **True Negatives ($TN$, Legitimate as Legitimate)**: **1,192**

2. **10-Feature Random Forest Model (`random_forest_10_features.pkl`)**:
   - **Accuracy**: **90.9543%** (0.9095)
   - **Precision**: **90.4564%** (0.9046)
   - **Recall**: **88.9796%** (0.8898)
   - **F1 Score**: **89.7119%** (0.8971)
   - **Confusion Matrix** (True $\backslash$ Predicted on labels $[-1, 1]$):
     - **True Positives ($TP$, Phishing as Phishing)**: **872**
     - **False Negatives ($FN$, Phishing as Legitimate)**: **108**
     - **False Positives ($FP$, Legitimate as Phishing)**: **92**
     - **True Negatives ($TN$, Legitimate as Legitimate)**: **1,139**

The 20-feature model achieves an accuracy of 95.70% by leveraging deep HTML content and JavaScript behaviors, while the 10-feature model maintains 90.95% accuracy using only lightweight lexical and network signals.

```
                    +------------------------------------+
                    |   Curated Phishing Dataset (UCI)   |
                    |         (11,055 Samples)           |
                    +------------------------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
    +------------------------------+       +------------------------------+
    | 20-Feature Dataset (Full)    |       | 10-Feature Dataset (Reduced) |
    | 20 Features + Result Label   |       | 10 Features + Result Label   |
    +------------------------------+       +------------------------------+
                   |                                       |
                   v                                       v
    +------------------------------+       +------------------------------+
    | Stratified 80/20 Split       |       | Stratified 80/20 Split       |
    | Train: 8,844 | Test: 2,211   |       | Train: 8,844 | Test: 2,211   |
    +------------------------------+       +------------------------------+
                   |                                       |
                   v                                       v
    +------------------------------+       +------------------------------+
    | ColumnTransformer (Passthru) |       | ColumnTransformer (Passthru) |
    +------------------------------+       +------------------------------+
                   |                                       |
                   v                                       v
    +------------------------------+       +------------------------------+
    | RandomForestClassifier (300) |       | RandomForestClassifier (300) |
    | class_weight='balanced'      |       | class_weight='balanced'      |
    +------------------------------+       +------------------------------+
                   |                                       |
                   v                                       v
    +------------------------------+       +------------------------------+
    | models/random_forest.pkl     |       | models/random_forest_10_     |
    | Test Accuracy: 95.70%        |       |   features.pkl               |
    | Test F1 Score: 95.11%        |       | Test Accuracy: 90.95%        |
    +------------------------------+       | Test F1 Score: 89.71%        |
                                           +------------------------------+
```
*Figure 5.2: Model Training and Evaluation Workflow*

---

## 5.4 Testing Methodology

### 5.4.1 Testing Environment and Framework

The platform underwent comprehensive verification using an automated testing framework built on **`pytest 9.1.1`** operating in Python 3.13 on a 64-bit Windows environment. The test suite comprises **188 automated tests** distributed across 18 specialized test modules in the `tests/` directory:
- **Unit Testing**: Evaluated individual feature extraction functions across Section 1 (Lexical), Section 2 (Network & SSL), Section 3 (HTML DOM), and Section 4 (JavaScript behaviors).
- **Contract and Schema Validation**: Validated that 10-dimensional and 20-dimensional feature arrays preserve strict column ordering and reject missing or out-of-bounds values.
- **Classifier and Probability Verification**: Tested model loading, probability matrix structures (`predict_proba()`), class index mapping (`model.classes_`), and missing-class fallbacks.
- **Routing and Security Verification**: Tested 13 HTTP status and Content-Type scenarios, redirect loops, socket timeouts, and Server-Side Request Forgery (SSRF) defense against loopback/private IP addresses (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`).
- **Threat Intelligence Integration**: Tested ChromaDB vector database ingestion, data anonymization, KMeans cluster generation, frequency distributions, and defensive recommendation rule triggering.

### 5.4.2 Testing Plan and Execution Results

Table 5.2 summarizes the testing plan, specifying test objectives, conditions, expected results, and actual verified outcomes.

---

### Table 5.2: Testing Plan and Empirical Verification

| Test Area / Objective | Test Case Description | Test Input / Condition | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Input Validation** | Rejection of empty or whitespace inputs | `""` or `"   "` | Rejected at UI validator; returns `False`, `"URL not valid"` | Rejected immediately without invoking network or models | **Passed** |
| **Input Validation** | Rejection of malformed URLs | `"invalid_host"`, `".bad.com"` | Rejected; returns `False`, `"URL not valid"` | Blocked by `validate_url_format()` | **Passed** |
| **SSRF Security Defense** | Blocking private / loopback IP addresses | `http://127.0.0.1/admin`, `http://192.168.1.1` | Flagged as non-routable private IP; diverted safely to Pipeline B without network fetch | Network probe suppressed; handled safely | **Passed** |
| **Feature Extraction** | Lexical feature vector contract (10-Feature) | Standard test URL with known structure | Exactly 10 integer features in canonical order; values $\in \{-1, 0, 1\}$ | Shape `(10,)`, strictly ternary, correct indices | **Passed** |
| **Feature Extraction** | HTML DOM extraction (20-Feature) | Mocked HTML with external anchors and iframes | Correct counts for `Request_URL`, `URL_of_Anchor`, and `Iframe` | Feature values matched mathematical thresholds exactly | **Passed** |
| **Network Feature** | SSL Certificate Verification | HTTPS URL with trusted CA and age $\ge 1\text{ yr}$ | `SSLfinal_State = 1` | Correctly identified trusted issuer and age; returned `1` | **Passed** |
| **Network Feature** | SSL Handshake Failure / HTTP fallback | Plain `http://` or unreachable domain | `SSLfinal_State = -1` | Handshake failure trapped safely; returned `-1` | **Passed** |
| **Adaptive Routing** | Responsive HTML resource routing | HTTP `200 OK`, `Content-Type: text/html` | Routed to Pipeline A; extracts 20 features; uses `random_forest.pkl` | Correctly routed to Pipeline A; 20 features processed | **Passed** |
| **Adaptive Routing** | Non-HTML / Error resource routing | HTTP `404 Not Found` or `application/javascript` | Routed to Pipeline B; extracts 10 features; uses `random_forest_10_features.pkl` | Correctly routed to Pipeline B; 10 features processed | **Passed** |
| **Adaptive Routing** | Unreachable host / Connection timeout | Non-existent domain or closed port | Network timeout trapped; fallback to Pipeline B | Trapped within 3.0s timeout; Pipeline B executed | **Passed** |
| **Model Inference** | 20-Feature Classifier execution | 20-dimensional feature vector input | Output label $\in \{-1, 1\}$, calibrated probability $\in [0.0, 1.0]$ | Valid prediction generated; probability calibrated | **Passed** |
| **Model Inference** | 10-Feature Classifier execution | 10-dimensional feature vector input | Output label $\in \{-1, 1\}$, calibrated probability $\in [0.0, 1.0]$ | Valid prediction generated; probability calibrated | **Passed** |
| **Decision Rule** | Pipeline B SSL Decision Rule | Pipeline B input with `SSLfinal_State = -1` | Predicted label forced to `-1` (Phishing) | Overrode probability threshold; assigned `-1` | **Passed** |
| **Vector DB Storage** | Phishing vector ingestion | URL classified as Phishing (`-1`) | Vector stored in ChromaDB; zero URL strings in metadata | Stored with timestamp and model tag; URL omitted | **Passed** |
| **Privacy Protection** | Legitimate prediction exclusion | URL classified as Legitimate (`+1`) | Not stored in ChromaDB vector database | Ingestion bypassed; database count unchanged | **Passed** |
| **Threat Analytics** | Unsupervised clustering & recommendations | Triggered on phishing ingestion | Recomputes KMeans clusters ($k=4$), updates 20 recommendation rules | Clusters refreshed; recommendation diff generated | **Passed** |
| **System Latency** | Offline / Lexical feature extraction | String parsing and regular expressions | Execution time $< 100\text{ ms}$ | Executed in $< 15\text{ ms}$ on local CPU | **Passed** |
| **System Latency** | Live Network / Socket inspection | SSL handshake + 10-port socket probe | Execution time bounded by socket timeouts ($\le 4.0\text{ s}$) | Bounded within configured socket timeouts | **Passed** |

---

## 5.5 Prototype Validation

### 5.5.1 Validation Setup and Interface Workflow

The integrated platform was validated end-to-end using the Streamlit web dashboard (`app.py`), connected directly to the backend prediction router, classifier models, and ChromaDB vector threat intelligence repository. The web interface exposes three primary functional views:
1. **View 1: URL Input and Analysis Trigger**: Allows analysts to input URLs, select the execution mode (automatic adaptive routing vs. forced pipeline selection), and initiate analysis.
2. **View 2: Classification Results and Evidence Inspector**: Displays the binary prediction verdict (**Phishing** or **Legitimate**), calibrated risk probability score, active pipeline indicator, server response metrics, and an interactive **Extracted Feature Vector Table** presenting human-readable feature names mapped to their extracted ternary values.
3. **View 3: Threat Activity and Defensive Recommendation Dashboard**: Visualizes global threat intelligence derived from ChromaDB, including total phishing cases, high-risk signal frequency rankings, archetypal KMeans threat clusters, and an automated defensive action plan generated by the 20-rule recommendation engine.

### 5.5.2 Real-World Test Cases and Verified Outputs

The prototype was validated against diverse real-world URL archetypes representing distinct network conditions:

1. **Test Case 1: Verified Legitimate Domain (`https://example.com`)**
   - **Network Probe**: Returned HTTP `200 OK`, `Content-Type: text/html`.
   - **Pipeline Selected**: **Pipeline A (20-Feature Full DOM Pipeline)**.
   - **Extracted Signals**: Clean lexical structure (`having_IP_Address: 1`, `Prefix_Suffix: 1`), trusted TLS certificate (`SSLfinal_State: 1`), and zero suspicious form actions (`SFH: 1`).
   - **Prediction Verdict**: **Legitimate (`+1`)**; Phishing Probability: **0.00%**.
   - **Threat DB Action**: No storage in ChromaDB; client data remains private.

2. **Test Case 2: Active Phishing URL with IP Address Host (`http://222.137.23.188:37413/i`)**
   - **Network Probe**: Direct IP host with unusual high port; remote server connection timed out.
   - **Pipeline Selected**: **Pipeline B (10-Feature Reduced Pipeline)** via automated fallback.
   - **Extracted Signals**: Raw IP address used (`having_IP_Address: -1`), non-standard port (`port: -1`), plain HTTP scheme and missing SSL certificate (`SSLfinal_State: -1`).
   - **Prediction Verdict**: **Phishing (`-1`)**; Phishing Probability: **100.00%** (enforced by the Pipeline B SSL decision rule).
   - **Threat DB Action**: The 10-feature vector was ingested into the `phishing_threat_vectors_10` collection in ChromaDB without saving the URL string; threat analytics and defensive recommendation rules were refreshed.

3. **Test Case 3: Invalid Input Handling (`http://invalid host.com` and `.bad.com`)**
   - **Pre-check Validation**: Intercepted by `src/ui_validator.py`.
   - **Outcome**: Streamlit interface presented an error banner stating `"URL not valid"`. No backend HTTP requests or machine learning models were triggered, safeguarding network resources.

```
+----------------------------------------------------------------------------------------------------+
|                                    PHISHING DETECTION SYSTEM                                       |
|  [ Analyze URL ]  |  [ Extracted Feature Vector ]  |  [ Threat Intelligence Dashboard ]            |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  Enter URL to analyze:                                                                             |
|  [ http://222.137.23.188:37413/i                                                      ] [ Analyze ]|
|                                                                                                    |
|  ================================================================================================  |
|  RESULT: PHISHING DETECTED (-1)                     CONFIDENCE SCORE: 100.00%                      |
|  Pipeline: Pipeline B (10-Feature Reduced)          Status: Connection Timed Out (Fallback)        |
|  ================================================================================================  |
|                                                                                                    |
|  Extracted Feature Vector:                                                                         |
|  +--------------------+------------+--------------------+------------------+---------------------+ |
|  | having_IP_Address  | URL_Length | Shortining_Service | having_At_Symbol | double_slash_redir  | |
|  | -1 (Phishing)      | 1 (Safe)   | 1 (Safe)           | 1 (Safe)         | 1 (Safe)            | |
|  +--------------------+------------+--------------------+------------------+---------------------+ |
|  | Prefix_Suffix      | Sub_Domain | HTTPS_token        | SSLfinal_State   | port                | |
|  | 1 (Safe)           | 1 (Safe)   | 1 (Safe)           | -1 (Phishing)    | -1 (Non-standard)   | |
|  +--------------------+------------+--------------------+------------------+---------------------+ |
|                                                                                                    |
|  Threat Intelligence & Automated Recommendations:                                                  |
|  - Ingested anonymous vector into ChromaDB collection: phishing_threat_vectors_10                   |
|  - Active Threat Cluster: Cluster 2 (IP-Hosted / Certificate-Deficient Campaigns)                  |
|  - Defensive Action: Block raw numeric IP traffic on ingress perimeter firewalls                  |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```
*Figure 5.3: Completed Prototype — Input and Prediction Output (Interface Layout and Output Verification)*
*(Note: A full graphical screenshot from the running Streamlit web browser session can be captured and inserted into Figure 5.3 for the final printed report).*
