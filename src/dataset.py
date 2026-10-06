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
    "RightClick"
]

REQUIRED_20_COLUMNS = EXPECTED_19_FEATURES + ["Result"]

ALLOWED_FEATURE_VALUES = {
    "having_IP_Address": {"-1", "1"},
    "URL_Length": {"-1", "0", "1"},
    "Shortining_Service": {"-1", "1"},
    "having_At_Symbol": {"-1", "1"},
    "double_slash_redirecting": {"-1", "1"},
    "Prefix_Suffix": {"-1", "1"},
    "having_Sub_Domain": {"-1", "0", "1"},
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

UNWANTED_COLUMNS = [
    "SSLfinal_State",
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

def inspect_dataset(arff_path="data/original/Training Dataset.arff", report_path="data/dataset_validation_report.txt"):
    df, meta = load_arff_to_dataframe(arff_path)

    # Check malformed rows by raw line parsing of @data section
    declared_attr_count = 0
    in_data_section = False
    malformed_rows_fewer = 0
    malformed_rows_more = 0
    total_data_lines = 0

    with open(arff_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("%"):
                continue
            if stripped.lower().startswith("@attribute"):
                declared_attr_count += 1
            elif stripped.lower().startswith("@data"):
                in_data_section = True
            elif in_data_section:
                total_data_lines += 1
                tokens = stripped.split(",")
                if len(tokens) < declared_attr_count:
                    malformed_rows_fewer += 1
                elif len(tokens) > declared_attr_count:
                    malformed_rows_more += 1

    total_malformed_rows = malformed_rows_fewer + malformed_rows_more

    actual_rows, actual_cols = df.shape
    actual_attributes = list(meta.names())

    # Attribute verification
    missing_attrs = [attr for attr in EXPECTED_31_ATTRIBUTES if attr not in actual_attributes]
    unexpected_attrs = [attr for attr in actual_attributes if attr not in EXPECTED_31_ATTRIBUTES]
    order_matches = (actual_attributes == EXPECTED_31_ATTRIBUTES)

    # 19 features verification
    all_19_present = all(feat in actual_attributes for feat in EXPECTED_19_FEATURES)
    result_present = "Result" in actual_attributes

    # Check categorical values, declared allowed values, and unexpected values
    attr_categories = {}
    unexpected_values_per_col = {}
    has_unexpected_categorical_values = False

    for attr in actual_attributes:
        col_type, col_params = meta[attr]
        allowed_values = set(col_params) if col_type == 'nominal' else set()
        
        # observed unique values
        observed_values = set(df[attr].dropna().unique())
        
        # If allowed values were bytes, decode for fair comparison
        allowed_values_str = {v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in allowed_values}
        observed_values_str = {str(v) for v in observed_values}
        
        diff = observed_values_str - allowed_values_str if allowed_values_str else set()
        if diff:
            has_unexpected_categorical_values = True
            unexpected_values_per_col[attr] = list(diff)
        
        attr_categories[attr] = {
            "type": col_type,
            "allowed": sorted(list(allowed_values_str)),
            "observed": sorted(list(observed_values_str)),
            "unexpected": sorted(list(diff))
        }

    # Missing values
    missing_counts = df.isnull().sum()
    missing_percentages = (df.isnull().sum() / len(df)) * 100
    has_missing_values = bool((missing_counts > 0).any())

    # Result distribution
    result_col = df["Result"].astype(str)
    result_counts = result_col.value_counts().to_dict()
    count_neg1 = result_counts.get("-1", 0)
    count_pos1 = result_counts.get("1", 0)
    pct_neg1 = (count_neg1 / actual_rows) * 100 if actual_rows else 0
    pct_pos1 = (count_pos1 / actual_rows) * 100 if actual_rows else 0

    final_status = "PASSED" if (
        order_matches and 
        all_19_present and 
        result_present and 
        total_malformed_rows == 0 and 
        not has_unexpected_categorical_values
    ) else "FAILED"

    # Print validation report to console
    print("=" * 60)
    print("DATASET VALIDATION RESULTS")
    print("=" * 60)
    print(f"Dataset path: {arff_path}")
    print(f"Total Rows: {actual_rows}")
    print(f"Total Columns: {actual_cols}")
    print(f"All 31 expected attributes exist: {'YES' if not missing_attrs and not unexpected_attrs else 'NO'}")
    print(f"Attribute order matches: {'YES' if order_matches else 'NO'}")
    print(f"19 required features present: {'YES' if all_19_present else 'NO'}")
    print(f"Result present: {'YES' if result_present else 'NO'}")
    print(f"Malformed rows: {total_malformed_rows} (fewer: {malformed_rows_fewer}, more: {malformed_rows_more})")
    print(f"Missing values exist: {'YES' if has_missing_values else 'NO'}")
    print(f"Result class distribution:")
    print(f"  Result = -1: {count_neg1} ({pct_neg1:.2f}%)")
    print(f"  Result =  1: {count_pos1} ({pct_pos1:.2f}%)")
    print(f"Unexpected categorical values: {'YES' if has_unexpected_categorical_values else 'NO'}")
    print(f"Final validation status: {final_status}")
    print("=" * 60)

    # Generate data/dataset_validation_report.txt
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write("==================================================\n")
        rf.write("DATASET VALIDATION REPORT\n")
        rf.write("==================================================\n\n")
        rf.write(f"1. Dataset path:\n   {os.path.abspath(arff_path)}\n\n")
        rf.write(f"2. Number of rows:\n   {actual_rows}\n\n")
        rf.write(f"3. Number of columns:\n   {actual_cols}\n\n")
        rf.write("4. Complete actual attribute list:\n")
        for idx, attr in enumerate(actual_attributes, start=1):
            rf.write(f"   {idx}. {attr}\n")
        rf.write("\n")
        rf.write("5. Attribute order verification:\n")
        rf.write(f"   Order exactly matches expected: {'YES' if order_matches else 'NO'}\n")
        if missing_attrs:
            rf.write(f"   Missing attributes: {missing_attrs}\n")
        if unexpected_attrs:
            rf.write(f"   Unexpected attributes: {unexpected_attrs}\n")
        rf.write("\n")
        rf.write("6. All 19 required features verification:\n")
        rf.write(f"   19 required features present: {'YES' if all_19_present else 'NO'}\n")
        for f_name in EXPECTED_19_FEATURES:
            rf.write(f"   - {f_name}: {'PRESENT' if f_name in actual_attributes else 'MISSING'}\n")
        rf.write("\n")
        rf.write("7. Result target verification:\n")
        rf.write(f"   Result present: {'YES' if result_present else 'NO'}\n\n")
        rf.write("8. Allowed values from the ARFF and 9. Actual observed values:\n")
        for attr in actual_attributes:
            info = attr_categories[attr]
            rf.write(f"   Attribute: {attr}\n")
            rf.write(f"     Type: {info['type']}\n")
            rf.write(f"     Allowed values in ARFF: {info['allowed']}\n")
            rf.write(f"     Observed unique values: {info['observed']}\n")
            rf.write(f"     Unexpected values: {info['unexpected'] if info['unexpected'] else 'None'}\n")
        rf.write("\n")
        rf.write("10. Missing-value counts and 11. Missing-value percentages:\n")
        for attr in actual_attributes:
            cnt = missing_counts[attr]
            pct = missing_percentages[attr]
            rf.write(f"   - {attr}: count = {cnt}, percentage = {pct:.2f}%\n")
        rf.write("\n")
        rf.write(f"12. Malformed-row count:\n")
        rf.write(f"   Total malformed rows: {total_malformed_rows}\n")
        rf.write(f"   Rows with fewer than 31 values: {malformed_rows_fewer}\n")
        rf.write(f"   Rows with more than 31 values: {malformed_rows_more}\n\n")
        rf.write("13. Result class distribution:\n")
        rf.write(f"   Total rows: {actual_rows}\n")
        rf.write(f"   Result = -1: {count_neg1} ({pct_neg1:.2f}%)\n")
        rf.write(f"   Result =  1: {count_pos1} ({pct_pos1:.2f}%)\n\n")
        rf.write(f"14. Final validation status:\n")
        rf.write(f"   {final_status}\n")

    return final_status

def create_19_feature_dataset(
    arff_path="data/original/Training Dataset.arff",
    output_csv_path="data/phishing_19_features.csv"
):
    df_original, meta = load_arff_to_dataframe(arff_path)
    df_filtered = df_original[REQUIRED_20_COLUMNS].copy()
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    df_filtered.to_csv(output_csv_path, index=False)
    return True

def validate_19_feature_dataset(
    csv_path="data/phishing_19_features.csv",
    arff_path="data/original/Training Dataset.arff",
    report_path="data/phishing_19_features_validation_report.txt"
):
    print("=" * 60)
    print("PERFORMING FINAL VALIDATION OF 19-FEATURE DATASET")
    print("=" * 60)

    # Step 1: Load CSV
    if not os.path.exists(csv_path):
        print(f"CSV file not found: {csv_path}")
        return False
    df_csv = pd.read_csv(csv_path)
    csv_rows, csv_cols = df_csv.shape
    csv_col_names = list(df_csv.columns)

    print(f"Step 1: Loaded CSV from {csv_path}")
    print(f"  Rows: {csv_rows}")
    print(f"  Columns count: {csv_cols}")
    print(f"  Column names: {csv_col_names}")

    failure_reasons = []

    # Step 2: Verify column count == 20
    if csv_cols != 20:
        failure_reasons.append(f"Column count is {csv_cols}, expected exactly 20")

    # Step 3: Verify column names and order
    missing_cols = [c for c in REQUIRED_20_COLUMNS if c not in csv_col_names]
    unexpected_cols = [c for c in csv_col_names if c not in REQUIRED_20_COLUMNS]
    duplicate_cols = [c for c in set(csv_col_names) if csv_col_names.count(c) > 1]
    order_exact = (csv_col_names == REQUIRED_20_COLUMNS)

    if missing_cols:
        failure_reasons.append(f"Missing columns: {missing_cols}")
    if unexpected_cols:
        failure_reasons.append(f"Unexpected columns: {unexpected_cols}")
    if duplicate_cols:
        failure_reasons.append(f"Duplicate columns: {duplicate_cols}")
    if not order_exact:
        failure_reasons.append("Column order does not match exact required order")

    # Step 4: Verify feature count
    input_features = [c for c in csv_col_names if c != "Result"]
    has_target = "Result" in csv_col_names
    if len(input_features) != 19:
        failure_reasons.append(f"Input features count is {len(input_features)}, expected exactly 19")
    if not has_target:
        failure_reasons.append("Target column 'Result' is missing")

    # Step 5: Check missing values
    missing_counts = df_csv.isnull().sum()
    missing_percentages = (missing_counts / csv_rows) * 100
    has_missing = bool((missing_counts > 0).any())
    if has_missing:
        failure_reasons.append(f"Missing values found: {missing_counts[missing_counts > 0].to_dict()}")

    # Step 6: Check unique values against allowed values
    actual_unique_values = {}
    invalid_values = {}
    has_invalid_values = False

    for col in csv_col_names:
        actual_vals = sorted([str(x) for x in df_csv[col].dropna().unique()])
        actual_unique_values[col] = actual_vals
        allowed = ALLOWED_FEATURE_VALUES.get(col, set())
        invalid = sorted(list(set(actual_vals) - allowed))
        if invalid:
            has_invalid_values = True
            invalid_values[col] = invalid

    if has_invalid_values:
        failure_reasons.append(f"Invalid categorical values found: {invalid_values}")

    # Step 7: Verify target
    result_vals = set(actual_unique_values.get("Result", []))
    if not result_vals.issubset({"-1", "1"}) or not result_vals:
        failure_reasons.append(f"Result contains unexpected classes: {result_vals}")

    result_series = df_csv["Result"].astype(str)
    count_neg1 = int((result_series == "-1").sum())
    count_pos1 = int((result_series == "1").sum())
    pct_neg1 = (count_neg1 / csv_rows) * 100 if csv_rows else 0
    pct_pos1 = (count_pos1 / csv_rows) * 100 if csv_rows else 0

    # Step 8: Verify data types and interpretability
    dtypes_dict = {col: str(df_csv[col].dtype) for col in csv_col_names}

    # Step 9: Verify row count against original ARFF
    df_orig, _ = load_arff_to_dataframe(arff_path)
    orig_rows = len(df_orig)
    rows_match = (csv_rows == orig_rows)
    if not rows_match:
        failure_reasons.append(f"Row count mismatch: Original ARFF={orig_rows}, CSV={csv_rows}")

    # Step 10: Verify data integrity against original
    cell_mismatches = []
    if order_exact and rows_match:
        for col in REQUIRED_20_COLUMNS:
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

    # Step 11: Class distribution print
    print("\nCLASS DISTRIBUTION")
    print("==================")
    print(f"Result = -1:")
    print(f"Count: {count_neg1}")
    print(f"Percentage: {pct_neg1:.2f}%")
    print()
    print(f"Result = 1:")
    print(f"Count: {count_pos1}")
    print(f"Percentage: {pct_pos1:.2f}%")
    print()
    print(f"Total: {csv_rows}")

    # Final status determination
    passed = (len(failure_reasons) == 0)
    final_status = "PASS" if passed else "FAIL"

    print("\n" + "=" * 60)
    print(f"VALIDATION STATUS: {final_status}")
    if not passed:
        print("Failed checks:")
        for r in failure_reasons:
            print(f" - {r}")
    print("=" * 60)

    # Step 12: Create validation report file
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write("==================================================\n")
        rf.write("PHISHING 19-FEATURE DATASET FINAL VALIDATION REPORT\n")
        rf.write("==================================================\n\n")
        rf.write(f"1. Dataset path:\n   {os.path.abspath(csv_path)}\n\n")
        rf.write(f"2. Row count:\n   {csv_rows}\n\n")
        rf.write(f"3. Column count:\n   {csv_cols}\n\n")
        rf.write("4. Exact column order:\n")
        for idx, col in enumerate(csv_col_names, start=1):
            rf.write(f"   {idx}. {col}\n")
        rf.write("\n")
        rf.write(f"5. Feature count:\n   {len(input_features)}\n\n")
        rf.write(f"6. Target column:\n   Result\n\n")
        rf.write("7. Missing values for every column:\n")
        for col in csv_col_names:
            rf.write(f"   - {col}: count = {missing_counts[col]}, percentage = {missing_percentages[col]:.2f}%\n")
        rf.write("\n")
        rf.write("8. Actual unique values for every column:\n")
        for col in csv_col_names:
            rf.write(f"   - {col}: {actual_unique_values[col]}\n")
        rf.write("\n")
        rf.write("9. Invalid-value check:\n")
        rf.write(f"   Invalid values found: {'YES' if has_invalid_values else 'NO'}\n")
        if has_invalid_values:
            rf.write(f"   Details: {invalid_values}\n")
        rf.write("\n")
        rf.write("10. Data type information:\n")
        for col in csv_col_names:
            rf.write(f"   - {col}: {dtypes_dict[col]}\n")
        rf.write("\n")
        rf.write(f"11. Original ARFF row count:\n   {orig_rows}\n\n")
        rf.write(f"12. CSV row count:\n   {csv_rows}\n\n")
        rf.write(f"13. Row count comparison:\n   Matches: {'YES' if rows_match else 'NO'}\n\n")
        rf.write("14. Cell-level integrity comparison result:\n")
        rf.write(f"   Cell mismatches count: {len(cell_mismatches)}\n")
        if cell_mismatches:
            for m in cell_mismatches[:10]:
                rf.write(f"     Row {m['row']}, Column '{m['column']}': orig='{m['orig']}', csv='{m['csv']}'\n")
        else:
            rf.write("   Every cell exactly matches the original ARFF dataset.\n")
        rf.write("\n")
        rf.write("15. Result class distribution:\n")
        rf.write(f"   Result = -1: Count = {count_neg1}, Percentage = {pct_neg1:.2f}%\n")
        rf.write(f"   Result = 1:  Count = {count_pos1}, Percentage = {pct_pos1:.2f}%\n")
        rf.write(f"   Total rows:  {csv_rows}\n\n")
        rf.write(f"16. Final validation status:\n   {final_status}\n")
        if not passed:
            rf.write("   Fail reasons:\n")
            for r in failure_reasons:
                rf.write(f"     - {r}\n")

    return passed

if __name__ == "__main__":
    inspect_dataset()
    create_19_feature_dataset()
    validate_19_feature_dataset()
