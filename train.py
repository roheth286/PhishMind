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

EXPECTED_19_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "port",
    "HTTPS_token",
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Iframe",
    "Redirect",
    "on_mouseover",
    "RightClick",
]

REQUIRED_20_COLUMNS = EXPECTED_19_FEATURES + ["Result"]


def train_and_evaluate():
    data_path = "data/phishing_19_features.csv"
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)

    # Step 1: Load Data
    print("=" * 60)
    print("STEP 1: LOADING DATA")
    print("=" * 60)
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found at: {data_path}")

    df = pd.read_csv(data_path)
    total_rows, total_cols = df.shape
    print(f"Loaded CSV: {total_rows} rows, {total_cols} columns")

    if total_rows != 11055:
        print(f"WARNING: Expected 11,055 rows, but found {total_rows} rows.")

    if total_cols != 20:
        raise ValueError(f"Expected 20 columns, found {total_cols}")

    if list(df.columns) != REQUIRED_20_COLUMNS:
        raise ValueError("Column order does not match expected 20 columns.")

    # Step 2: Separate X and y
    print("\n" * 0 + "=" * 60)
    print("STEP 2: SEPARATING X AND y")
    print("=" * 60)
    X = df[EXPECTED_19_FEATURES].copy()
    y = df["Result"].astype(int).copy()
    print(f"X shape: {X.shape}, y shape: {y.shape}")

    # Step 3: Verify Target
    print("\n" * 0 + "=" * 60)
    print("STEP 3: VERIFYING TARGET")
    print("=" * 60)
    count_neg1 = int((y == -1).sum())
    count_pos1 = int((y == 1).sum())
    pct_neg1 = (count_neg1 / total_rows) * 100
    pct_pos1 = (count_pos1 / total_rows) * 100
    print(f"Result = -1: {count_neg1} ({pct_neg1:.2f}%)")
    print(f"Result =  1: {count_pos1} ({pct_pos1:.2f}%)")
    print(f"Total: {total_rows}")

    # Step 4: Train / Test Split
    print("\n" * 0 + "=" * 60)
    print("STEP 4: TRAIN / TEST SPLIT (80/20 Stratified, random_state=42)")
    print("=" * 60)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=42
    )
    n_train = len(X_train)
    n_test = len(X_test)
    print(f"Training rows: {n_train}")
    print(f"Test rows: {n_test}")

    # Step 5: Preprocessing
    print("\n" * 0 + "=" * 60)
    print("STEP 5: PREPROCESSING PIPELINE OBJECT")
    print("=" * 60)
    # Using standard sklearn ColumnTransformer as a pass-through selector to guarantee
    # feature preservation, order preservation, and standard library pickling compatibility.
    preprocessor = ColumnTransformer(
        transformers=[
            ("passthrough_features", "passthrough", EXPECTED_19_FEATURES)
        ],
        remainder="drop"
    )
    X_train_proc = preprocessor.fit_transform(X_train)
    X_test_proc = preprocessor.transform(X_test)
    print(f"Preprocessed X_train shape: {X_train_proc.shape}")
    print(f"Preprocessed X_test shape: {X_test_proc.shape}")

    # Step 6 & 7: Random Forest Model & Training
    print("\n" * 0 + "=" * 60)
    print("STEP 6 & 7: RANDOM FOREST TRAINING")
    print("=" * 60)
    rf = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        max_features="sqrt",
        n_jobs=-1
    )
    rf.fit(X_train_proc, y_train)
    print(f"Model trained successfully.")
    print(f"Number of trees: {rf.n_estimators}")
    print(f"Random state: {rf.random_state}")
    print(f"Feature count: {X_train.shape[1]}")

    # Step 8: Evaluate on Test Set
    print("\n" * 0 + "=" * 60)
    print("STEP 8: TEST SET EVALUATION (Positive class = 1)")
    print("=" * 60)
    y_pred = rf.predict(X_test_proc)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1)
    rec = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    cm = confusion_matrix(y_test, y_pred, labels=[-1, 1])

    print(f"Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision: {prec:.4f} ({prec*100:.2f}%)")
    print(f"Recall:    {rec:.4f} ({rec*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"Confusion Matrix (labels: [-1, 1]):\n{cm}")

    # Step 9: Probabilities
    print("\n" * 0 + "=" * 60)
    print("STEP 9: PREDICT_PROBA VERIFICATION")
    print("=" * 60)
    probs = rf.predict_proba(X_test_proc)
    print(f"Classes in model: {rf.classes_}")
    print(f"Probability matrix shape: {probs.shape}")
    print(f"Sample predict_proba output (first row): {probs[0]}")
    if probs.shape == (n_test, 2):
        print("predict_proba() verified successfully: exactly 2 class probabilities per test row.")

    # Step 10 & 12: Feature Importance
    print("\n" * 0 + "=" * 60)
    print("STEP 10 & 12: FEATURE IMPORTANCE")
    print("=" * 60)
    importances = rf.feature_importances_
    feat_imp_df = pd.DataFrame({
        "Feature": EXPECTED_19_FEATURES,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

    feat_imp_path = os.path.join(models_dir, "feature_importance.csv")
    feat_imp_df.to_csv(feat_imp_path, index=False)
    print(f"Saved feature importance to {feat_imp_path}")
    print("\nTop 10 Features by Importance:")
    print(feat_imp_df.head(10).to_string(index=False))

    # Step 11: Confusion Matrix Plot
    print("\n" * 0 + "=" * 60)
    print("STEP 11: SAVING CONFUSION MATRIX PLOT")
    print("=" * 60)
    cm_path = os.path.join(models_dir, "confusion_matrix.png")
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
    ax.set_title('Random Forest Confusion Matrix (Test Set)', fontsize=13, pad=20)
    plt.tight_layout()
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"Saved confusion matrix plot to {cm_path}")

    # Step 13: Save Model
    rf_model_path = os.path.join(models_dir, "random_forest.pkl")
    joblib.dump(rf, rf_model_path)
    print(f"Saved model to {rf_model_path}")

    # Step 14: Save Preprocessing Object
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    joblib.dump(preprocessor, scaler_path)
    print(f"Saved preprocessor to {scaler_path}")

    # Step 15: Save Training Metrics
    metrics_path = os.path.join(models_dir, "training_metrics.txt")
    with open(metrics_path, "w", encoding="utf-8") as f:
        f.write("==================================================\n")
        f.write("RANDOM FOREST TRAINING & EVALUATION METRICS\n")
        f.write("==================================================\n\n")
        f.write(f"Dataset row count: {total_rows}\n")
        f.write(f"Feature count: {len(EXPECTED_19_FEATURES)}\n")
        f.write("Target column: Result\n")
        f.write("Class distribution:\n")
        f.write(f"  Result = -1: {count_neg1} ({pct_neg1:.2f}%)\n")
        f.write(f"  Result =  1: {count_pos1} ({pct_pos1:.2f}%)\n")
        f.write(f"Train row count: {n_train}\n")
        f.write(f"Test row count: {n_test}\n")
        f.write("Train/Test split ratio: 80% Train / 20% Test\n")
        f.write("Random state: 42\n")
        f.write("n_estimators: 300\n")
        f.write("max_features: sqrt\n")
        f.write("class_weight: balanced\n\n")
        f.write("EVALUATION METRICS (Test Set, positive class = 1):\n")
        f.write(f"Accuracy:  {acc:.6f} ({acc*100:.2f}%)\n")
        f.write(f"Precision: {prec:.6f} ({prec*100:.2f}%)\n")
        f.write(f"Recall:    {rec:.6f} ({rec*100:.2f}%)\n")
        f.write(f"F1 Score:  {f1:.6f} ({f1*100:.2f}%)\n\n")
        f.write("CONFUSION MATRIX (True \\ Pred: [-1, 1]):\n")
        f.write(f"  TN (-1 as -1): {cm[0, 0]}\n")
        f.write(f"  FP (-1 as  1): {cm[0, 1]}\n")
        f.write(f"  FN ( 1 as -1): {cm[1, 0]}\n")
        f.write(f"  TP ( 1 as  1): {cm[1, 1]}\n")
    print(f"Saved training metrics to {metrics_path}")

    # Step 19: Final Training Checks
    print("\n" * 0 + "=" * 60)
    print("STEP 19: FINAL TRAINING CHECKS & MODEL RELOAD")
    print("=" * 60)
    loaded_rf = joblib.load(rf_model_path)
    loaded_preprocessor = joblib.load(scaler_path)
    test_proc_reloaded = loaded_preprocessor.transform(X_test)
    reloaded_pred = loaded_rf.predict(test_proc_reloaded)
    reloaded_probs = loaded_rf.predict_proba(test_proc_reloaded)

    reloaded_pred_match = np.array_equal(y_pred, reloaded_pred)
    reloaded_probs_match = np.allclose(probs, reloaded_probs)

    print("1. Model object exists in memory: YES")
    print(f"2. models/random_forest.pkl exists: {'YES' if os.path.exists(rf_model_path) else 'NO'}")
    print(f"3. models/scaler.pkl exists: {'YES' if os.path.exists(scaler_path) else 'NO'}")
    print(f"4. models/feature_importance.csv exists: {'YES' if os.path.exists(feat_imp_path) else 'NO'}")
    print(f"5. models/confusion_matrix.png exists: {'YES' if os.path.exists(cm_path) else 'NO'}")
    print(f"6. models/training_metrics.txt exists: {'YES' if os.path.exists(metrics_path) else 'NO'}")
    print("7. Model can be loaded back using joblib: YES")
    print(f"8. Loaded model can call predict(): YES (Matches: {'YES' if reloaded_pred_match else 'NO'})")
    print(f"9. Loaded model can call predict_proba(): YES (Matches: {'YES' if reloaded_probs_match else 'NO'})")
    print(f"10. Exactly one prediction per test row: {'YES' if len(reloaded_pred) == n_test else 'NO'} ({len(reloaded_pred)})")
    print(f"11. predict_proba() returns probabilities for both classes: {'YES' if reloaded_probs.shape[1] == 2 else 'NO'}")
    print(f"12. Exactly 19 feature importance values: {'YES' if len(rf.feature_importances_) == 19 else 'NO'}")
    print("=" * 60)

    return True


if __name__ == "__main__":
    train_and_evaluate()
