import os
import sys
from scipy.io import arff
import pandas as pd
import numpy as np

EXPECTED_31_ATTRIBUTES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
    "Result"
]

EXPECTED_20_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
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
    "RightClick"
]

REQUIRED_21_COLUMNS = EXPECTED_20_FEATURES + ["Result"]

ALLOWED_20_FEATURE_VALUES = {
    "having_IP_Address": {"-1", "1"},
    "URL_Length": {"-1", "0", "1"},
    "Shortining_Service": {"-1", "1"},
    "having_At_Symbol": {"-1", "1"},
    "double_slash_redirecting": {"-1", "1"},
    "Prefix_Suffix": {"-1", "1"},
    "having_Sub_Domain": {"-1", "0", "1"},
    "SSLfinal_State": {"-1", "0", "1"},
    "port": {"-1", "1"},
    "HTTPS_token": {"-1", "1"},
    "Favicon": {"-1", "1"},
    "Request_URL": {"-1", "1"},
    "URL_of_Anchor": {"-1", "0", "1"},
    "Links_in_tags": {"-1", "0", "1"},
    "SFH": {"-1", "0", "1"},
    "Submitting_to_email": {"-1", "1"},
    "Iframe": {"-1", "1"},
    "Redirect": {"-1", "0", "1"},
    "on_mouseover": {"-1", "1"},
    "RightClick": {"-1", "1"},
    "Result": {"-1", "1"}
}

UNWANTED_10_COLUMNS = [
    "Domain_registeration_length",
    "Abnormal_URL",
    "popUpWidnow",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report"
]

def load_arff_to_dataframe(arff_path="data/original/Training Dataset.arff"):
    if not os.path.exists(arff_path):
        raise FileNotFoundError(f"Dataset file not found at: {arff_path}")
    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)
    for col in df.columns:
        if df[col].dtype == object or df[col].dtype == 'O':
            try:
                df[col] = df[col].apply(lambda x: x.decode('utf-8') if isinstance(x, bytes) else str(x))
            except Exception:
                pass
    return df, meta

def create_20_feature_dataset(
    arff_path="data/original/Training Dataset.arff",
    output_csv_path="data/phishing_20_features.csv"
):
    print("=" * 60)
    print("CREATING 20-FEATURE DATASET")
    print("=" * 60)
    df_original, meta = load_arff_to_dataframe(arff_path)
    df_filtered = df_original[REQUIRED_21_COLUMNS].copy()
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    df_filtered.to_csv(output_csv_path, index=False)
    print(f"Saved 20-feature dataset ({df_filtered.shape[0]} rows, {df_filtered.shape[1]} cols) to {output_csv_path}")
    return True

def validate_20_feature_dataset(
    csv_path="data/phishing_20_features.csv",
    arff_path="data/original/Training Dataset.arff",
    report_path="data/phishing_20_features_validation_report.txt"
):
    print("=" * 60)
    print("VALIDATING 20-FEATURE DATASET")
    print("=" * 60)

    # 1. File exists
    if not os.path.exists(csv_path):
        print(f"CSV file not found: {csv_path}")
        return False

    df_csv = pd.read_csv(csv_path)
    csv_rows, csv_cols = df_csv.shape
    csv_col_names = list(df_csv.columns)
    failure_reasons = []

    print(f"Loaded CSV: {csv_rows} rows, {csv_cols} columns")

    # 2. Row count matches original ARFF
    df_orig, meta = load_arff_to_dataframe(arff_path)
    orig_rows, orig_cols = df_orig.shape
    rows_match = (csv_rows == orig_rows)
    if not rows_match:
        failure_reasons.append(f"Row count mismatch: ARFF={orig_rows}, CSV={csv_rows}")

    # 3. Column count is exactly 21
    if csv_cols != 21:
        failure_reasons.append(f"Column count is {csv_cols}, expected exactly 21")

    # 4. Exactly 20 feature columns exist & 5. Result exists & 6. Column order is exactly correct
    if csv_col_names != REQUIRED_21_COLUMNS:
        failure_reasons.append("Columns and their order do not match REQUIRED_21_COLUMNS")

    # 7. No unwanted columns exist
    present_unwanted = [c for c in UNWANTED_10_COLUMNS if c in csv_col_names]
    if present_unwanted:
        failure_reasons.append(f"Unwanted columns present: {present_unwanted}")

    # 8. SSLfinal_State exists exactly once
    ssl_count = csv_col_names.count("SSLfinal_State")
    if ssl_count != 1:
        failure_reasons.append(f"SSLfinal_State count is {ssl_count}, expected exactly 1")

    # 9. No previous feature was accidentally removed & 10. No additional feature was added
    input_features = [c for c in csv_col_names if c != "Result"]
    if input_features != EXPECTED_20_FEATURES:
        failure_reasons.append("Input features list does not match EXPECTED_20_FEATURES")

    # 11. No missing values exist
    missing_counts = df_csv.isnull().sum()
    missing_percentages = (missing_counts / csv_rows) * 100
    if (missing_counts > 0).any():
        failure_reasons.append(f"Missing values found: {missing_counts[missing_counts > 0].to_dict()}")

    # 12. No invalid categorical values exist & 13. Result contains only -1 and 1
    actual_unique_values = {}
    invalid_values = {}
    has_invalid_values = False

    for col in csv_col_names:
        actual_vals = sorted([str(x) for x in df_csv[col].dropna().unique()])
        actual_unique_values[col] = actual_vals
        allowed = ALLOWED_20_FEATURE_VALUES.get(col, set())
        invalid = sorted(list(set(actual_vals) - allowed))
        if invalid:
            has_invalid_values = True
            invalid_values[col] = invalid

    if has_invalid_values:
        failure_reasons.append(f"Invalid categorical values found: {invalid_values}")

    # SSLfinal_State specific check
    ssl_actual = actual_unique_values.get("SSLfinal_State", [])
    print(f"SSLfinal_State unique values: {ssl_actual}")
    if set(ssl_actual) - {"-1", "0", "1"}:
        failure_reasons.append(f"Invalid SSLfinal_State values: {set(ssl_actual) - {'-1', '0', '1'}}")

    # Result specific check
    result_vals = set(actual_unique_values.get("Result", []))
    if not result_vals.issubset({"-1", "1"}):
        failure_reasons.append(f"Result contains unexpected classes: {result_vals}")

    result_series = df_csv["Result"].astype(str)
    count_neg1 = int((result_series == "-1").sum())
    count_pos1 = int((result_series == "1").sum())
    pct_neg1 = (count_neg1 / csv_rows) * 100 if csv_rows else 0
    pct_pos1 = (count_pos1 / csv_rows) * 100 if csv_rows else 0

    # 14. Row-level / cell-level integrity check
    cell_mismatches = []
    if csv_col_names == REQUIRED_21_COLUMNS and rows_match:
        for col in REQUIRED_21_COLUMNS:
            orig_col = df_orig[col].astype(str)
            csv_col = df_csv[col].astype(str)
            diffs = (orig_col != csv_col)
            if diffs.any():
                for idx in np.where(diffs)[0]:
                    cell_mismatches.append({
                        "row": int(idx),
                        "column": col,
                        "orig": orig_col.iloc[idx],
                        "csv": csv_col.iloc[idx]
                    })
    if cell_mismatches:
        failure_reasons.append(f"{len(cell_mismatches)} cell-level mismatches with original dataset")

    # Status
    passed = (len(failure_reasons) == 0)
    final_status = "PASS" if passed else "FAIL"

    print("\n" + "=" * 60)
    print(f"VALIDATION STATUS: {final_status}")
    if not passed:
        print("Failed checks:")
        for r in failure_reasons:
            print(f" - {r}")
    print("=" * 60)

    # Step 5: Final dataset validation report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write("==================================================\n")
        rf.write("PHISHING 20-FEATURE DATASET FINAL VALIDATION REPORT\n")
        rf.write("==================================================\n\n")
        rf.write(f"1. Source dataset:\n   {os.path.abspath(arff_path)}\n\n")
        rf.write(f"2. Output dataset:\n   {os.path.abspath(csv_path)}\n\n")
        rf.write(f"3. Row count:\n   {csv_rows}\n\n")
        rf.write(f"4. Column count:\n   {csv_cols}\n\n")
        rf.write("5. Exact column order:\n")
        for idx, col in enumerate(csv_col_names, start=1):
            rf.write(f"   {idx}. {col}\n")
        rf.write("\n")
        rf.write(f"6. 20 feature names:\n")
        for idx, feat in enumerate(input_features, start=1):
            rf.write(f"   {idx}. {feat}\n")
        rf.write("\n")
        rf.write("7. Target name:\n   Result\n\n")
        rf.write("8. Unique values for every feature:\n")
        for col in csv_col_names:
            rf.write(f"   - {col}: {actual_unique_values[col]}\n")
        rf.write("\n")
        rf.write("9. Missing values for every column:\n")
        for col in csv_col_names:
            rf.write(f"   - {col}: count = {missing_counts[col]}, percentage = {missing_percentages[col]:.2f}%\n")
        rf.write("\n")
        rf.write("10. Invalid-value check:\n")
        rf.write(f"   Invalid values found: {'YES' if has_invalid_values else 'NO'}\n")
        if has_invalid_values:
            rf.write(f"   Details: {invalid_values}\n")
        rf.write("\n")
        rf.write("11. Result class distribution:\n")
        rf.write(f"   Result = -1: Count = {count_neg1}, Percentage = {pct_neg1:.2f}%\n")
        rf.write(f"   Result =  1: Count = {count_pos1}, Percentage = {pct_pos1:.2f}%\n")
        rf.write(f"   Total rows:  {csv_rows}\n\n")
        rf.write(f"12. Row-count comparison:\n")
        rf.write(f"   Original ARFF rows = {orig_rows}, CSV rows = {csv_rows} (Matches: {'YES' if rows_match else 'NO'})\n\n")
        rf.write("13. Cell-level integrity comparison result:\n")
        rf.write(f"   Cell mismatches count: {len(cell_mismatches)}\n")
        if cell_mismatches:
            for m in cell_mismatches[:10]:
                rf.write(f"     Row {m['row']}, Column '{m['column']}': orig='{m['orig']}', csv='{m['csv']}'\n")
        else:
            rf.write("   Every cell exactly matches the original ARFF dataset.\n")
        rf.write("\n")
        rf.write(f"14. Final validation status:\n   {final_status}\n")
        if not passed:
            rf.write("   Fail reasons:\n")
            for r in failure_reasons:
                rf.write(f"     - {r}\n")

    return passed

if __name__ == "__main__":
    create_20_feature_dataset()
    validate_20_feature_dataset()
