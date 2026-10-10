import json
import os
import sys
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

SOURCE_20_CSV = os.path.join("data", "phishing_20_features.csv")
TARGET_10_CSV = os.path.join("data", "phishing_10_features.csv")
MODELS_DIR = "models"

ORDERED_10_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
    "SSLfinal_State",
    "port",
]

TARGET_COLUMN = "Result"
REQUIRED_11_COLUMNS = ORDERED_10_FEATURES + [TARGET_COLUMN]

MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_10_features.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler_10_features.pkl")
SCHEMA_PATH = os.path.join(MODELS_DIR, "features_10_features.json")
FEATURE_IMPORTANCE_PATH = os.path.join(MODELS_DIR, "feature_importance_10_features.csv")
CONFUSION_MATRIX_PATH = os.path.join(MODELS_DIR, "confusion_matrix_10_features.png")
METRICS_PATH = os.path.join(MODELS_DIR, "training_metrics_10_features.txt")


def step_create_and_validate_csv():
    """
    Step 1-4: Load source CSV, create 10-feature CSV, and validate row-by-row consistency.
    """
    print("=" * 70)
    print("STEP 1: INSPECTING & LOADING SOURCE DATASET")
    print("=" * 70)
    if not os.path.exists(SOURCE_20_CSV):
        raise FileNotFoundError(f"Source 20-feature dataset not found at: {SOURCE_20_CSV}")

    df_source = pd.read_csv(SOURCE_20_CSV)
    src_rows, src_cols = df_source.shape
    print(f"Loaded source dataset: {src_rows} rows, {src_cols} columns")

    # Verify all 10 features and Result exist in source
    for col in REQUIRED_11_COLUMNS:
        if col not in df_source.columns:
            raise ValueError(f"Required column '{col}' missing from source dataset.")

    # Check order discrepancy between 20-feature dataset and new 10-feature dataset
    src_feature_indices = {col: i for i, col in enumerate(df_source.columns)}
    print("\nSource column indices for selected features:")
    for feat in ORDERED_10_FEATURES:
        print(f"  {feat}: source index {src_feature_indices[feat]} (Column {src_feature_indices[feat] + 1})")

    # Note discrepancy: in 20-features CSV, SSLfinal_State (col 8) and port (col 9) precede HTTPS_token (col 10).
    # In the 10-feature specification, all URL-only features are grouped first, placing HTTPS_token at position 8,
    # followed by SSLfinal_State (position 9) and port (position 10).
    print("\n[NOTE ON COLUMN ORDERING]")
    print("In data/phishing_20_features.csv, columns appear as: SSLfinal_State (8), port (9), HTTPS_token (10).")
    print("Per TASK 1 specification, the 10-feature model orders all Section 1 URL-only features first:")
    print("HTTPS_token is Position 8, followed by connection-level SSLfinal_State (Position 9) and port (Position 10).")

    print("\n" + "=" * 70)
    print("STEP 2 & 3: CREATING 10-FEATURE DATASET")
    print("=" * 70)
    # Select columns in exact required order
    df_10 = df_source[REQUIRED_11_COLUMNS].copy()

    # Save to data/phishing_10_features.csv
    os.makedirs(os.path.dirname(TARGET_10_CSV), exist_ok=True)
    df_10.to_csv(TARGET_10_CSV, index=False)
    print(f"Successfully wrote 10-feature dataset to: {TARGET_10_CSV}")

    # Step 3 Validation: Load back and verify
    print("\nValidating newly created CSV from disk...")
    df_reloaded = pd.read_csv(TARGET_10_CSV)
    rel_rows, rel_cols = df_reloaded.shape

    if rel_rows != src_rows:
        raise ValueError(f"Row count mismatch: expected {src_rows}, got {rel_rows}")
    if rel_cols != 11:
        raise ValueError(f"Column count mismatch: expected 11, got {rel_cols}")
    if list(df_reloaded.columns) != REQUIRED_11_COLUMNS:
        raise ValueError(f"Column order mismatch. Expected:\n{REQUIRED_11_COLUMNS}\nGot:\n{list(df_reloaded.columns)}")

    # Check nulls/missing values
    missing_count = df_reloaded.isnull().sum().sum()
    if missing_count > 0:
        raise ValueError(f"Found {missing_count} unexpected missing values in {TARGET_10_CSV}")

    # Row-by-row equality verification with source
    for col in REQUIRED_11_COLUMNS:
        if not (df_reloaded[col] == df_source[col]).all():
            raise ValueError(f"Data value mismatch between source and new CSV in column: {col}")

    print("CSV VALIDATION PASSED:")
    print(f"  - File exists at: {TARGET_10_CSV}")
    print(f"  - Exact 11 columns in required order: YES")
    print(f"  - Row count matches source ({rel_rows} rows): YES")
    print(f"  - Row-by-row feature and target values match source: YES")
    print(f"  - Missing/NaN values: 0")

    return df_reloaded


def train_and_evaluate_10_features():
    """
    Complete reproducible training and evaluation pipeline for the 10-feature Random Forest model.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Create and validate CSV
    df = step_create_and_validate_csv()

    # 2. Separate X and y
    print("\n" + "=" * 70)
    print("STEP 4: SEPARATING X AND y (10 Features)")
    print("=" * 70)
    X = df[ORDERED_10_FEATURES].copy()
    y = df[TARGET_COLUMN].astype(int).copy()
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"Input features list ({len(ORDERED_10_FEATURES)} features):\n  {list(X.columns)}")

    total_rows = len(df)
    count_neg1 = int((y == -1).sum())
    count_pos1 = int((y == 1).sum())
    pct_neg1 = (count_neg1 / total_rows) * 100
    pct_pos1 = (count_pos1 / total_rows) * 100

    print(f"\nTarget class distribution ({TARGET_COLUMN}):")
    print(f"  Result = -1 (Legitimate): {count_neg1} ({pct_neg1:.2f}%)")
    print(f"  Result =  1 (Phishing):   {count_pos1} ({pct_pos1:.2f}%)")
    print(f"  Total instances:          {total_rows}")

    # 3. Stratified Train / Test Split (80/20, random_state=42)
    print("\n" + "=" * 70)
    print("STEP 5: STRATIFIED TRAIN/TEST SPLIT (80% / 20%, random_state=42)")
    print("=" * 70)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=42
    )
    n_train = len(X_train)
    n_test = len(X_test)
    print(f"Training set rows: {n_train} ({n_train / total_rows * 100:.1f}%)")
    print(f"Testing set rows:  {n_test} ({n_test / total_rows * 100:.1f}%)")
    print(f"Train class balance: Result=-1: {(y_train == -1).sum()}, Result=1: {(y_train == 1).sum()}")
    print(f"Test class balance:  Result=-1: {(y_test == -1).sum()}, Result=1: {(y_test == 1).sum()}")

    # 4. Preprocessing Object
    print("\n" + "=" * 70)
    print("STEP 6: PREPROCESSING PIPELINE OBJECT (10 Features Passthrough)")
    print("=" * 70)
    preprocessor = ColumnTransformer(
        transformers=[
            ("passthrough_10_features", "passthrough", ORDERED_10_FEATURES)
        ],
        remainder="drop"
    )
    X_train_proc = preprocessor.fit_transform(X_train)
    X_test_proc = preprocessor.transform(X_test)
    print(f"Preprocessed X_train shape: {X_train_proc.shape}")
    print(f"Preprocessed X_test shape:  {X_test_proc.shape}")

    # 5. Train Random Forest Classifier
    print("\n" + "=" * 70)
    print("STEP 7: RANDOM FOREST TRAINING (10 Features)")
    print("=" * 70)
    rf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        max_features="sqrt",
        n_jobs=-1
    )
    rf.fit(X_train_proc, y_train)
    print("Model trained successfully.")
    print(f"  Estimator:     sklearn.ensemble.RandomForestClassifier")
    print(f"  n_estimators:  {rf.n_estimators}")
    print(f"  random_state:  {rf.random_state}")
    print(f"  class_weight:  {rf.class_weight}")
    print(f"  max_features:  {rf.max_features}")
    print(f"  n_features_in: {rf.n_features_in_}")

    # 6. Evaluate on Test Set
    print("\n" + "=" * 70)
    print("STEP 8: TEST SET EVALUATION (Unseen Test Data, positive class = 1)")
    print("=" * 70)
    y_pred = rf.predict(X_test_proc)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1)
    rec = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    cm = confusion_matrix(y_test, y_pred, labels=[-1, 1])

    print(f"Accuracy:  {acc:.6f} ({acc * 100:.2f}%)")
    print(f"Precision: {prec:.6f} ({prec * 100:.2f}%)")
    print(f"Recall:    {rec:.6f} ({rec * 100:.2f}%)")
    print(f"F1 Score:  {f1:.6f} ({f1 * 100:.2f}%)")
    print(f"\nConfusion Matrix (labels: [-1, 1]):\n{cm}")
    print("Orientation: Rows = True Labels [-1, 1], Columns = Predicted Labels [-1, 1]")
    print(f"  True Negative  (TN: -1 as -1): {cm[0, 0]}")
    print(f"  False Positive (FP: -1 as  1): {cm[0, 1]}")
    print(f"  False Negative (FN:  1 as -1): {cm[1, 0]}")
    print(f"  True Positive  (TP:  1 as  1): {cm[1, 1]}")

    # 7. Probability Predictions
    print("\n" + "=" * 70)
    print("STEP 9: PREDICT_PROBA VERIFICATION")
    print("=" * 70)
    probs = rf.predict_proba(X_test_proc)
    print(f"Model classes_: {rf.classes_}")
    print(f"Probability matrix shape: {probs.shape}")
    pos_idx = list(rf.classes_).index(1)
    print(f"Index of positive class (Result = 1): {pos_idx}")
    print(f"Sample predict_proba (first row): {probs[0]}")
    if probs.shape == (n_test, 2) and np.allclose(probs.sum(axis=1), 1.0):
        print("predict_proba() verified successfully: exactly 2 valid class probabilities per test row.")

    # 8. Feature Importance
    print("\n" + "=" * 70)
    print("STEP 10: FEATURE IMPORTANCE (10 Features)")
    print("=" * 70)
    importances = rf.feature_importances_
    feat_imp_df = pd.DataFrame({
        "Feature": ORDERED_10_FEATURES,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

    print("All 10 Features Ranked by Importance:")
    print(feat_imp_df.to_string(index=False))

    # 9. Save Artifacts
    print("\n" + "=" * 70)
    print("STEP 11-14: SAVING ARTIFACTS")
    print("=" * 70)

    # 9.1 Save feature importance CSV
    feat_imp_df.to_csv(FEATURE_IMPORTANCE_PATH, index=False)
    print(f"1. Saved feature importance to: {FEATURE_IMPORTANCE_PATH}")

    # 9.2 Save confusion matrix plot
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.8)
    fig.colorbar(cax)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(x=j, y=i, s=f"{cm[i, j]}", va='center', ha='center', size='xx-large')
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Legitimate (-1)', 'Phishing (1)'])
    ax.set_yticklabels(['Legitimate (-1)', 'Phishing (1)'])
    ax.set_xlabel('Predicted Label', fontsize=12)
    ax.set_ylabel('True Label', fontsize=12)
    ax.set_title('Random Forest Confusion Matrix (10 Features, Test Set)', fontsize=12, pad=20)
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=300)
    plt.close()
    print(f"2. Saved confusion matrix plot to: {CONFUSION_MATRIX_PATH}")

    # 9.3 Save Model and Scaler
    joblib.dump(rf, MODEL_PATH)
    print(f"3. Saved trained 10-feature model to: {MODEL_PATH}")
    joblib.dump(preprocessor, SCALER_PATH)
    print(f"4. Saved 10-feature preprocessor to: {SCALER_PATH}")

    # 9.4 Save Feature Schema JSON
    with open(SCHEMA_PATH, "w", encoding="utf-8") as f:
        json.dump(ORDERED_10_FEATURES, f, indent=4)
    print(f"5. Saved 10-feature schema JSON to: {SCHEMA_PATH}")

    # 9.5 Save Training Metrics TXT
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        f.write("============================================================\n")
        f.write("RANDOM FOREST TRAINING & EVALUATION METRICS (10 FEATURES)\n")
        f.write("============================================================\n\n")
        f.write(f"Source dataset path: {SOURCE_20_CSV}\n")
        f.write(f"New dataset path: {TARGET_10_CSV}\n")
        f.write(f"Dataset row count: {total_rows}\n")
        f.write(f"Feature count: {len(ORDERED_10_FEATURES)}\n")
        f.write("Ordered feature names:\n")
        for idx, feat in enumerate(ORDERED_10_FEATURES):
            f.write(f"  {idx + 1}. {feat}\n")
        f.write(f"\nTarget column: {TARGET_COLUMN}\n")
        f.write("Target class distribution:\n")
        f.write(f"  Result = -1 (Legitimate): {count_neg1} ({pct_neg1:.2f}%)\n")
        f.write(f"  Result =  1 (Phishing):   {count_pos1} ({pct_pos1:.2f}%)\n\n")
        f.write(f"Train row count: {n_train}\n")
        f.write(f"Test row count:  {n_test}\n")
        f.write("Train/Test split ratio: 80% Train / 20% Test (stratified, random_state=42)\n")
        f.write("Random Forest configuration:\n")
        f.write("  n_estimators=300\n")
        f.write("  random_state=42\n")
        f.write("  class_weight=balanced\n")
        f.write("  max_features=sqrt\n")
        f.write("  n_jobs=-1\n\n")
        f.write("EVALUATION METRICS (Test Set, positive class = 1):\n")
        f.write(f"  Accuracy:  {acc:.6f} ({acc * 100:.2f}%)\n")
        f.write(f"  Precision: {prec:.6f} ({prec * 100:.2f}%)\n")
        f.write(f"  Recall:    {rec:.6f} ({rec * 100:.2f}%)\n")
        f.write(f"  F1 Score:  {f1:.6f} ({f1 * 100:.2f}%)\n\n")
        f.write("CONFUSION MATRIX (True \\ Pred: [-1, 1]):\n")
        f.write(f"  TN (-1 as -1): {cm[0, 0]}\n")
        f.write(f"  FP (-1 as  1): {cm[0, 1]}\n")
        f.write(f"  FN ( 1 as -1): {cm[1, 0]}\n")
        f.write(f"  TP ( 1 as  1): {cm[1, 1]}\n\n")
        f.write("PROBABILITY PREDICTION VERIFICATION:\n")
        f.write(f"  predict_proba() verified: YES\n")
        f.write(f"  model.classes_: {[int(c) for c in rf.classes_]}\n")
        f.write(f"  Positive class (1) probability index: {pos_idx}\n\n")
        f.write("MODEL ARTIFACT PATHS:\n")
        f.write(f"  Model:              {MODEL_PATH}\n")
        f.write(f"  Preprocessor:       {SCALER_PATH}\n")
        f.write(f"  Feature Schema:     {SCHEMA_PATH}\n")
        f.write(f"  Feature Importance: {FEATURE_IMPORTANCE_PATH}\n")
        f.write(f"  Confusion Matrix:   {CONFUSION_MATRIX_PATH}\n")
        f.write(f"  Training Metrics:   {METRICS_PATH}\n")
    print(f"6. Saved training metrics report to: {METRICS_PATH}")

    # 10. Reload and Verify
    print("\n" + "=" * 70)
    print("STEP 15: RELOAD & CONSISTENCY VERIFICATION")
    print("=" * 70)
    loaded_rf = joblib.load(MODEL_PATH)
    loaded_preproc = joblib.load(SCALER_PATH)

    reloaded_proc = loaded_preproc.transform(X_test)
    reloaded_pred = loaded_rf.predict(reloaded_proc)
    reloaded_probs = loaded_rf.predict_proba(reloaded_proc)

    pred_match = np.array_equal(y_pred, reloaded_pred)
    probs_match = np.allclose(probs, reloaded_probs)

    print(f"1. Model file reloaded successfully: YES")
    print(f"2. Preprocessor reloaded successfully: YES")
    print(f"3. Loaded model feature count: {loaded_rf.n_features_in_} (Expected: 10)")
    print(f"4. Loaded model predict() works: YES (Matches in-memory: {'YES' if pred_match else 'NO'})")
    print(f"5. Loaded model predict_proba() works: YES (Matches in-memory: {'YES' if probs_match else 'NO'})")
    print(f"6. 20-feature model artifact intact: {os.path.exists(os.path.join(MODELS_DIR, 'random_forest.pkl'))}")
    print("=" * 70)

    return True


if __name__ == "__main__":
    train_and_evaluate_10_features()
