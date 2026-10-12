# Section 7.1 — Model Performance Results

This document provides the verified model performance evaluation results for **Section 7.1: Model Performance Results** of the final project report.

---

## 7.1 Empirical Model Performance Evaluation

The phishing detection platform integrates two dedicated machine learning models:
1. **10-Feature Pipeline Model (`models/random_forest_10_features.pkl`)**: Designed for fast lexical and network inspection when remote servers are unreachable, redirected, or serve non-HTML content.
2. **20-Feature Pipeline Model (`models/random_forest.pkl`)**: Designed for comprehensive webpage DOM, JavaScript, network, and lexical inspection when active HTML content is verified.

Both models were trained using scikit-learn's `RandomForestClassifier` with balanced class weights (`n_estimators=300`, `max_features='sqrt'`, `random_state=42`) and evaluated on the exact held-out test partition consisting of **2,211 unseen records** (80% training / 20% test stratified split on 11,055 total records).

In all evaluations, the positive class is strictly defined as **Phishing (`Result = -1`)**, while the negative class represents **Legitimate (`Result = 1`)**.

---

### Table 7.1: Comparative Model Performance Results (Test Set Evaluation)

| Metric | 10-feature pipeline | 20-feature pipeline |
|---|---:|---:|
| Accuracy | 90.95% | 95.70% |
| Precision | 90.46% | 95.95% |
| Recall | 88.98% | 94.29% |
| F1-score | 89.71% | 95.11% |
| Test sample count | 2211 | 2211 |

---

## Detailed Performance Breakdown & Confusion Matrix

### 1. 10-Feature Pipeline Model (`models/random_forest_10_features.pkl`)

- **Dataset**: `data/phishing_10_features.csv` (11,055 total records; 8,844 train, 2,211 test)
- **Features (10)**: `having_IP_Address`, `URL_Length`, `Shortining_Service`, `having_At_Symbol`, `double_slash_redirecting`, `Prefix_Suffix`, `having_Sub_Domain`, `HTTPS_token`, `SSLfinal_State`, `port`.
- **Exact Floating-Point Metrics**:
  - Accuracy: `0.909543` $\rightarrow$ **90.95%**
  - Precision: `0.904564` $\rightarrow$ **90.46%**
  - Recall: `0.889796` $\rightarrow$ **88.98%**
  - F1-score: `0.897119` $\rightarrow$ **89.71%**
- **Confusion Matrix** (Labels: `[-1, 1]`):
  - **True Positives ($TP$, Phishing as Phishing)**: **872**
  - **False Negatives ($FN$, Phishing as Legitimate)**: **108**
  - **False Positives ($FP$, Legitimate as Phishing)**: **92**
  - **True Negatives ($TN$, Legitimate as Legitimate)**: **1,139**
  - Total Test Instances: $872 + 108 + 92 + 1139 = 2,211$

### 2. 20-Feature Pipeline Model (`models/random_forest.pkl`)

- **Dataset**: `data/phishing_20_features.csv` (11,055 total records; 8,844 train, 2,211 test)
- **Features (20)**: `having_IP_Address`, `URL_Length`, `Shortining_Service`, `having_At_Symbol`, `double_slash_redirecting`, `Prefix_Suffix`, `having_Sub_Domain`, `SSLfinal_State`, `port`, `HTTPS_token`, `Favicon`, `Request_URL`, `URL_of_Anchor`, `Links_in_tags`, `SFH`, `Submitting_to_email`, `Iframe`, `Redirect`, `on_mouseover`, `RightClick`.
- **Exact Floating-Point Metrics**:
  - Accuracy: `0.957033` $\rightarrow$ **95.70%**
  - Precision: `0.959502` $\rightarrow$ **95.95%**
  - Recall: `0.942857` $\rightarrow$ **94.29%**
  - F1-score: `0.951107` $\rightarrow$ **95.11%**
- **Confusion Matrix** (Labels: `[-1, 1]`):
  - **True Positives ($TP$, Phishing as Phishing)**: **924**
  - **False Negatives ($FN$, Phishing as Legitimate)**: **56**
  - **False Positives ($FP$, Legitimate as Phishing)**: **39**
  - **True Negatives ($TN$, Legitimate as Legitimate)**: **1,192**
  - Total Test Instances: $924 + 56 + 39 + 1192 = 2,211$

---

## Metric Verification Sources & Notes

All values in this section are verified directly against the project repository files:

1. **Primary Evaluation Reports**:
   - 10-Feature Metrics: [`models/training_metrics_10_features.txt`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/training_metrics_10_features.txt)
   - 20-Feature Metrics: [`models/training_metrics.txt`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/training_metrics.txt)
2. **Active Saved Models**:
   - [`models/random_forest_10_features.pkl`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/random_forest_10_features.pkl) (Loaded by `src/classifier.py` $\to$ `load_10_feature_model()`)
   - [`models/random_forest.pkl`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/random_forest.pkl) (Loaded by `src/classifier.py` $\to$ `load_model()`)
3. **Training Execution Scripts**:
   - [`train_10_features.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/train_10_features.py)
   - [`train.py`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/train.py)
4. **Source Datasets**:
   - [`data/phishing_10_features.csv`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/data/phishing_10_features.csv)
   - [`data/phishing_20_features.csv`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/data/phishing_20_features.csv)
5. **Secondary Note on Threshold Tuning**:
   - File [`models/model_config.json`](file:///c:/Users/tanvi/Downloads/CN_COURSE_PROJECT/models/model_config.json) records an optional experimental evaluation run with an adjusted decision threshold of `0.45` (yielding 90.95% accuracy, 89.88% precision, 89.69% recall, 89.79% F1 for 10-feature; and 95.61% accuracy, 95.56% precision, 94.49% recall, 95.02% F1 for 20-feature).
   - The primary metrics reported in Table 7.1 represent the baseline model performance at the standard classification threshold ($0.50$), matching the active classifiers and official training logs.
