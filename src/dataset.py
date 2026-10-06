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
    print("=" * 60)
    print("CREATING 19-FEATURE DATASET")
    print("=" * 60)
    
    # 1. Load original ARFF
    df_original, meta = load_arff_to_dataframe(arff_path)
    original_row_count = len(df_original)
    print(f"Loaded original ARFF: {original_row_count} rows, {df_original.shape[1]} columns.")

    # 2. Select ONLY the 20 required columns in exact specified order
    df_filtered = df_original[REQUIRED_20_COLUMNS].copy()

    # 3. Save to CSV
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    df_filtered.to_csv(output_csv_path, index=False)
    print(f"Saved filtered dataset to {output_csv_path}")

    # 4. Validation Checks
    print("\n" + "=" * 60)
    print("VALIDATING 19-FEATURE CSV DATASET")
    print("=" * 60)

    # 1. File exists
    file_exists = os.path.exists(output_csv_path)
    print(f"1. File exists: {'YES' if file_exists else 'NO'}")
    if not file_exists:
        raise FileNotFoundError(f"Output CSV not found at {output_csv_path}")

    # Load saved CSV to validate saved content
    df_csv = pd.read_csv(output_csv_path, dtype=str)
    csv_row_count, csv_col_count = df_csv.shape

    # 2. Number of rows matches original ARFF
    rows_match = (csv_row_count == original_row_count)
    print(f"2. Row count: Original={original_row_count}, CSV={csv_row_count} (Match: {'YES' if rows_match else 'NO'})")

    # 3. Number of columns is exactly 20
    cols_is_20 = (csv_col_count == 20)
    print(f"3. Column count is exactly 20: {'YES' if cols_is_20 else 'NO'} ({csv_col_count})")

    # 4. All 19 required feature columns exist
    csv_cols = list(df_csv.columns)
    all_19_exist = all(col in csv_cols for col in EXPECTED_19_FEATURES)
    print(f"4. All 19 required feature columns exist: {'YES' if all_19_exist else 'NO'}")

    # 5. Result exists
    result_exists = "Result" in csv_cols
    print(f"5. Result column exists: {'YES' if result_exists else 'NO'}")

    # 6. Column order is exactly correct
    order_exact = (csv_cols == REQUIRED_20_COLUMNS)
    print(f"6. Column order exactly matches required order: {'YES' if order_exact else 'NO'}")

    # 7. No unwanted columns exist
    present_unwanted = [col for col in UNWANTED_COLUMNS if col in csv_cols]
    unwanted_absent = (len(present_unwanted) == 0)
    print(f"7. Unwanted columns absent: {'YES' if unwanted_absent else 'NO'}")
    if present_unwanted:
        print(f"   Present unwanted columns: {present_unwanted}")

    # 8. No rows added or removed
    no_rows_changed = rows_match
    print(f"8. No rows added or removed: {'YES' if no_rows_changed else 'NO'}")

    # 9. Unique values per feature in generated CSV
    print("\n9. Feature Unique Values in generated CSV:")
    unexpected_cat_found = False
    for col in EXPECTED_19_FEATURES:
        unique_vals = sorted(list(df_csv[col].unique()))
        col_type, col_params = meta[col]
        allowed = sorted([v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in col_params])
        unexpected = set(unique_vals) - set(allowed)
        if unexpected:
            unexpected_cat_found = True
        print(f"   - {col:25}: {unique_vals} (Allowed: {allowed}, Unexpected: {list(unexpected)})")

    # 10. Result contains only original dataset classes
    result_vals = sorted(list(df_csv["Result"].unique()))
    original_result_vals = sorted(list(df_original["Result"].astype(str).unique()))
    result_classes_match = (set(result_vals) == set(original_result_vals))
    print(f"\n10. Result unique values: {result_vals} (Matches original: {'YES' if result_classes_match else 'NO'})")

    # ROW-LEVEL INTEGRITY CHECK
    print("\n" + "=" * 60)
    print("ROW-LEVEL INTEGRITY CHECK AGAINST ORIGINAL ARFF")
    print("=" * 60)
    
    mismatches = []
    # Compare row by row, column by column
    for col in REQUIRED_20_COLUMNS:
        orig_series = df_original[col].astype(str)
        csv_series = df_csv[col].astype(str)
        diff_mask = (orig_series != csv_series)
        if diff_mask.any():
            diff_indices = np.where(diff_mask)[0]
            for idx in diff_indices:
                mismatches.append({
                    "row": idx,
                    "column": col,
                    "original": orig_series.iloc[idx],
                    "generated": csv_series.iloc[idx]
                })

    integrity_passed = (len(mismatches) == 0)
    if integrity_passed:
        print("Row-level integrity check PASSED: All 11,055 rows and 20 columns match perfectly.")
    else:
        print(f"Row-level integrity check FAILED: {len(mismatches)} mismatches found.")
        for m in mismatches[:10]: # report up to 10
            print(f"   Row {m['row']}, Column '{m['column']}': original='{m['original']}', generated='{m['generated']}'")
        if len(mismatches) > 10:
            print(f"   ... and {len(mismatches) - 10} more.")

    validation_overall = (
        file_exists and
        rows_match and
        cols_is_20 and
        all_19_exist and
        result_exists and
        order_exact and
        unwanted_absent and
        not unexpected_cat_found and
        result_classes_match and
        integrity_passed
    )

    print("=" * 60)
    print(f"FINAL CREATION & VALIDATION STATUS: {'PASSED' if validation_overall else 'FAILED'}")
    print("=" * 60)

    return validation_overall

if __name__ == "__main__":
    inspect_dataset()
    create_19_feature_dataset()
