#!/usr/bin/env python3
"""
Standalone ChromaDB Threat Intelligence Vector Database Initialization Script.

Populates persistent ChromaDB collections with historical phishing feature vectors:
- 'phishing_10_features': from data/phishing_10_features.csv
- 'phishing_20_features': from data/phishing_20_features.csv

Requirements:
- Only rows where Result == -1 (Phishing) are imported.
- Exact feature ordering is enforced for both datasets.
- Vectors are validated against allowed categorical values.
- Result column is strictly excluded from vectors.
- No URLs, domains, or sensitive data are stored.
- Idempotent: re-running does not duplicate records.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.threat_vector_db import (
    ALLOWED_VALUES_10,
    ALLOWED_VALUES_20,
    COLLECTION_10_NAME,
    COLLECTION_20_NAME,
    DEFAULT_PERSIST_DIR,
    FEATURES_10,
    FEATURES_20,
    get_chroma_client,
    get_collection,
    validate_vector,
)


def validate_dataset_schema(
    df: pd.DataFrame,
    expected_features: Tuple[str, ...],
    target_column: str = "Result"
) -> None:
    """
    Validate that the DataFrame contains the expected features and target column.
    """
    missing_cols = [col for col in expected_features if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required feature columns in dataset: {missing_cols}")

    if target_column not in df.columns:
        raise ValueError(f"Missing required target column '{target_column}' in dataset.")

    # Check target column values
    unique_targets = set(df[target_column].dropna().unique())
    # Normalizing target values
    int_targets = set()
    for t in unique_targets:
        try:
            int_targets.add(int(t))
        except (ValueError, TypeError):
            raise ValueError(f"Target column contains non-integer value: {t}")

    if not int_targets.issubset({-1, 1}):
        raise ValueError(f"Unexpected target labels found: {int_targets}. Expected subset of {{-1, 1}}.")


def import_dataset(
    csv_filename: str,
    model_type: str,
    data_dir: str,
    persist_dir: str,
    batch_size: int = 500
) -> Dict[str, Any]:
    """
    Validate and import a dataset into its ChromaDB collection.
    Only rows where Result == -1 are imported.
    """
    csv_path = os.path.join(data_dir, csv_filename)
    print(f"\n[{model_type.upper()}] Starting import process for: {csv_path}")

    # Check for possible filename extensions or issues
    if not os.path.exists(csv_path):
        py_path = os.path.splitext(csv_path)[0] + ".py"
        if os.path.exists(py_path):
            raise FileNotFoundError(
                f"Expected CSV dataset not found at {csv_path}. A file with .py extension exists at {py_path}, "
                f"but a CSV file is required."
            )
        raise FileNotFoundError(f"Source dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    total_rows = len(df)
    print(f"[{model_type.upper()}] Rows read from CSV: {total_rows}")

    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    allowed_values = ALLOWED_VALUES_10 if model_type == "10_features" else ALLOWED_VALUES_20
    col_name = COLLECTION_10_NAME if model_type == "10_features" else COLLECTION_20_NAME

    # 1. Validate Schema
    validate_dataset_schema(df, expected_features, target_column="Result")

    # 2. Filter for Phishing rows only (Result == -1)
    df_phish = df[df["Result"].astype(int) == -1].copy()
    phishing_count = len(df_phish)
    legitimate_count = total_rows - phishing_count
    print(f"[{model_type.upper()}] Phishing rows selected (Result == -1): {phishing_count}")
    print(f"[{model_type.upper()}] Legitimate rows excluded (Result == 1): {legitimate_count}")

    if phishing_count == 0:
        raise ValueError(f"[{model_type.upper()}] No phishing rows found with Result == -1 in {csv_path}!")

    # 3. Retrieve or create ChromaDB collection
    collection = get_collection(model_type, persist_dir=persist_dir)
    initial_db_count = collection.count()
    print(f"[{model_type.upper()}] Existing collection '{col_name}' records: {initial_db_count}")

    # Fetch existing IDs to ensure idempotence
    existing_ids: Set[str] = set()
    if initial_db_count > 0:
        all_ids = collection.get()["ids"]
        existing_ids = set(all_ids)

    # 4. Construct and validate vectors with stable IDs
    ids_to_add: List[str] = []
    embeddings_to_add: List[List[float]] = []
    metadatas_to_add: List[Dict[str, Any]] = []
    skipped_existing = 0
    skipped_invalid = 0

    timestamp = datetime.now(timezone.utc).isoformat()
    feature_names_json = json.dumps(list(expected_features))

    for orig_idx, row in df_phish.iterrows():
        case_id = f"phish_{model_type}_row_{orig_idx:05d}"

        # If already present in collection, record as skipped for idempotence
        if case_id in existing_ids:
            skipped_existing += 1
            continue

        # Extract features in exact required order
        try:
            raw_vector = [row[feat] for feat in expected_features]
            validated_vec = validate_vector(model_type, raw_vector)
        except Exception as e:
            print(f"[{model_type.upper()}] Warning: Skipping invalid row {orig_idx}: {e}")
            skipped_invalid += 1
            continue

        metadata: Dict[str, Any] = {
            "case_id": case_id,
            "model_type": model_type,
            "feature_names": feature_names_json,
            "feature_values": json.dumps(validated_vec),
            "source_dataset": csv_filename,
            "observed_at": timestamp,
            "source_label": -1,
            "prediction_label": -1,
        }

        ids_to_add.append(case_id)
        embeddings_to_add.append([float(x) for x in validated_vec])
        metadatas_to_add.append(metadata)

    # 5. Insert new records in batches
    new_inserts = len(ids_to_add)
    if new_inserts > 0:
        print(f"[{model_type.upper()}] Inserting {new_inserts} new records into collection in batches of {batch_size}...")
        for i in range(0, new_inserts, batch_size):
            end_i = min(i + batch_size, new_inserts)
            collection.add(
                ids=ids_to_add[i:end_i],
                embeddings=embeddings_to_add[i:end_i],
                metadatas=metadatas_to_add[i:end_i]
            )
        print(f"[{model_type.upper()}] Successfully added {new_inserts} records.")
    else:
        print(f"[{model_type.upper()}] All {phishing_count} phishing records already exist in collection. Zero duplicate insertions.")

    final_db_count = collection.count()
    print(f"[{model_type.upper()}] Final collection record count: {final_db_count}")

    return {
        "model_type": model_type,
        "collection_name": col_name,
        "rows_read": total_rows,
        "phishing_selected": phishing_count,
        "legitimate_excluded": legitimate_count,
        "invalid_skipped": skipped_invalid,
        "already_existing": skipped_existing,
        "newly_inserted": new_inserts,
        "final_count": final_db_count,
    }


def initialize_threat_vector_db(
    data_dir: str = "data",
    persist_dir: str = DEFAULT_PERSIST_DIR
) -> bool:
    """
    Run full standalone initialization and import for both 10-feature and 20-feature datasets.
    """
    print("=" * 70)
    print("INITIALIZING STANDALONE CHROMADB THREAT INTELLIGENCE VECTOR DATABASE")
    print(f"Persistent Storage Directory: {os.path.abspath(persist_dir)}")
    print(f"Data Directory:               {os.path.abspath(data_dir)}")
    print("=" * 70)

    # 1. 10-Feature Dataset Import
    stats_10 = import_dataset(
        csv_filename="phishing_10_features.csv",
        model_type="10_features",
        data_dir=data_dir,
        persist_dir=persist_dir
    )

    # 2. 20-Feature Dataset Import
    stats_20 = import_dataset(
        csv_filename="phishing_20_features.csv",
        model_type="20_features",
        data_dir=data_dir,
        persist_dir=persist_dir
    )

    # Summary
    print("\n" + "=" * 70)
    print("IMPORT SUMMARY:")
    print("=" * 70)
    for stats in (stats_10, stats_20):
        print(f"\nCollection: '{stats['collection_name']}' ({stats['model_type']}):")
        print(f"  - Total source rows read:         {stats['rows_read']}")
        print(f"  - Phishing rows selected (=-1):   {stats['phishing_selected']}")
        print(f"  - Legitimate rows excluded (=1):  {stats['legitimate_excluded']}")
        print(f"  - Invalid rows skipped:           {stats['invalid_skipped']}")
        print(f"  - Records already in DB:          {stats['already_existing']}")
        print(f"  - Records newly inserted:         {stats['newly_inserted']}")
        print(f"  - Final collection count:         {stats['final_count']}")

    print("\n[STATUS] Database initialization completed successfully.")
    print("=" * 70)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Initialize ChromaDB Threat Intelligence historical phishing vector collections."
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Directory containing phishing_10_features.csv and phishing_20_features.csv (default: data)"
    )
    parser.add_argument(
        "--persist-dir",
        default=DEFAULT_PERSIST_DIR,
        help="ChromaDB persistent storage directory (default: chroma_db)"
    )

    args = parser.parse_args()

    try:
        success = initialize_threat_vector_db(
            data_dir=args.data_dir,
            persist_dir=args.persist_dir
        )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[ERROR] Database initialization failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
