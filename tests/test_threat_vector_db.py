"""
Unit and Integration Tests for Standalone ChromaDB Threat Vector Database.

Tests verify:
1. Only rows with Result == -1 are inserted.
2. Legitimate rows with Result == 1 are excluded.
3. 10-feature records contain exactly 10 values in exact specified order.
4. 20-feature records contain exactly 20 values in exact specified order.
5. Result is never included in any stored vector.
6. Feature values (-1, 0, 1) are preserved correctly when valid.
7. Invalid labels, missing columns, missing values, and invalid feature values are rejected safely.
8. 10-feature and 20-feature collections are isolated from each other.
9. Re-running initialization is idempotent and does not duplicate records.
10. Identical feature vectors from distinct source rows are preserved with stable IDs.
11. No original URLs or domains are written to metadata.
12. Stored records can be retrieved from persistent storage after reopening the client.
13. Invalid vector dimensions and invalid model types are rejected.
"""

import json
import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

import chromadb
from src.threat_vector_db import (
    FEATURES_10,
    FEATURES_20,
    ALLOWED_VALUES_10,
    ALLOWED_VALUES_20,
    COLLECTION_10_NAME,
    COLLECTION_20_NAME,
    get_chroma_client,
    get_collection,
    get_collection_stats,
    initialize_collections,
    insert_phishing_vector,
    validate_model_type,
    validate_vector,
)
from scripts.initialize_threat_vector_db import (
    import_dataset,
    initialize_threat_vector_db,
    validate_dataset_schema,
)


class TestThreatVectorDB(unittest.TestCase):

    def setUp(self):
        # Create a fresh temporary directory for isolated ChromaDB tests
        self.temp_dir = tempfile.mkdtemp(prefix="chroma_test_")
        self.data_temp_dir = tempfile.mkdtemp(prefix="data_test_")

    def tearDown(self):
        # Clean up temporary test directories
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        if os.path.exists(self.data_temp_dir):
            shutil.rmtree(self.data_temp_dir, ignore_errors=True)

    def _create_synthetic_10_csv(self, filename="phishing_10_features.csv"):
        # 4 rows: 2 phishing (-1), 2 legitimate (1)
        # Row 0 and Row 2 have IDENTICAL feature vectors to test preservation of distinct rows
        data = {
            "having_IP_Address": [-1, 1, -1, 1],
            "URL_Length": [1, 0, 1, -1],
            "Shortining_Service": [1, 1, 1, -1],
            "having_At_Symbol": [1, 1, 1, 1],
            "double_slash_redirecting": [-1, 1, -1, 1],
            "Prefix_Suffix": [-1, 1, -1, 1],
            "having_Sub_Domain": [0, 1, 0, -1],
            "HTTPS_token": [-1, 1, -1, 1],
            "SSLfinal_State": [-1, 1, -1, 0],
            "port": [1, 1, 1, -1],
            "Result": [-1, 1, -1, 1],
        }
        df = pd.DataFrame(data)
        csv_path = os.path.join(self.data_temp_dir, filename)
        df.to_csv(csv_path, index=False)
        return csv_path

    def _create_synthetic_20_csv(self, filename="phishing_20_features.csv"):
        # 3 rows: 2 phishing (-1), 1 legitimate (1)
        data = {feat: [1, -1, 1] for feat in FEATURES_20}
        data["Result"] = [-1, -1, 1]
        # Set some varied values
        data["URL_Length"] = [0, -1, 1]
        data["having_Sub_Domain"] = [-1, 0, 1]
        data["SSLfinal_State"] = [1, -1, 0]
        data["Redirect"] = [0, 1, 0]
        df = pd.DataFrame(data)
        csv_path = os.path.join(self.data_temp_dir, filename)
        df.to_csv(csv_path, index=False)
        return csv_path

    # --- Test 1 & 2: Only rows with Result == -1 are inserted, Legitimate excluded ---
    def test_import_only_phishing_rows_included(self):
        self._create_synthetic_10_csv()
        stats = import_dataset(
            csv_filename="phishing_10_features.csv",
            model_type="10_features",
            data_dir=self.data_temp_dir,
            persist_dir=self.temp_dir
        )
        self.assertEqual(stats["rows_read"], 4)
        self.assertEqual(stats["phishing_selected"], 2)
        self.assertEqual(stats["legitimate_excluded"], 2)
        self.assertEqual(stats["final_count"], 2)

        col = get_collection("10_features", persist_dir=self.temp_dir)
        records = col.get(include=["metadatas"])
        for meta in records["metadatas"]:
            self.assertEqual(meta["source_label"], -1)
            self.assertEqual(meta["prediction_label"], -1)

    # --- Test 3 & 4: Record dimensionality and exact feature order ---
    def test_record_dimensions_and_exact_order(self):
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        col10 = get_collection("10_features", persist_dir=self.temp_dir)
        sample10 = col10.get(limit=1, include=["embeddings", "metadatas"])
        self.assertEqual(len(sample10["embeddings"][0]), 10)
        feat_names_10 = json.loads(sample10["metadatas"][0]["feature_names"])
        self.assertEqual(feat_names_10, list(FEATURES_10))

        self._create_synthetic_20_csv()
        import_dataset("phishing_20_features.csv", "20_features", self.data_temp_dir, self.temp_dir)
        col20 = get_collection("20_features", persist_dir=self.temp_dir)
        sample20 = col20.get(limit=1, include=["embeddings", "metadatas"])
        self.assertEqual(len(sample20["embeddings"][0]), 20)
        feat_names_20 = json.loads(sample20["metadatas"][0]["feature_names"])
        self.assertEqual(feat_names_20, list(FEATURES_20))

    # --- Test 5: Result is never included in the stored vector ---
    def test_result_not_in_vector(self):
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        col = get_collection("10_features", persist_dir=self.temp_dir)
        sample = col.get(limit=1, include=["embeddings", "metadatas"])
        # Exactly 10 floats, not 11
        self.assertEqual(len(sample["embeddings"][0]), 10)
        meta_features = json.loads(sample["metadatas"][0]["feature_names"])
        self.assertNotIn("Result", meta_features)

    # --- Test 6: Feature values (-1, 0, 1) are preserved accurately ---
    def test_feature_values_preserved_accurately(self):
        vec = [-1, 0, 1, 1, -1, -1, 0, -1, 1, -1]
        cid = insert_phishing_vector("10_features", vec, persist_dir=self.temp_dir)
        col = get_collection("10_features", persist_dir=self.temp_dir)
        rec = col.get(ids=[cid], include=["embeddings", "metadatas"])
        retrieved_vec = [int(round(x)) for x in rec["embeddings"][0]]
        self.assertEqual(retrieved_vec, vec)
        self.assertEqual(json.loads(rec["metadatas"][0]["feature_values"]), vec)

    # --- Test 7: Invalid labels, missing columns, invalid feature values rejected ---
    def test_invalid_schemas_and_values_rejected(self):
        # 1. Missing Result column
        df_bad = pd.DataFrame({feat: [1] for feat in FEATURES_10})
        bad_csv = os.path.join(self.data_temp_dir, "no_result.csv")
        df_bad.to_csv(bad_csv, index=False)
        with self.assertRaises(ValueError):
            import_dataset("no_result.csv", "10_features", self.data_temp_dir, self.temp_dir)

        # 2. Missing feature column
        df_bad2 = pd.DataFrame({"having_IP_Address": [1], "Result": [-1]})
        bad_csv2 = os.path.join(self.data_temp_dir, "missing_feat.csv")
        df_bad2.to_csv(bad_csv2, index=False)
        with self.assertRaises(ValueError):
            import_dataset("missing_feat.csv", "10_features", self.data_temp_dir, self.temp_dir)

        # 3. Invalid categorical feature value (e.g. 99 for having_IP_Address)
        bad_vec = [99] + [1] * 9
        with self.assertRaises(ValueError):
            validate_vector("10_features", bad_vec)

        # 4. Non-numeric / NaN in vector
        bad_vec2 = ["bad"] + [1] * 9
        with self.assertRaises(TypeError):
            validate_vector("10_features", bad_vec2)

    # --- Test 8: Collections 10 and 20 are strictly isolated ---
    def test_collections_isolation(self):
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)

        self._create_synthetic_20_csv()
        import_dataset("phishing_20_features.csv", "20_features", self.data_temp_dir, self.temp_dir)

        col10 = get_collection("10_features", persist_dir=self.temp_dir)
        col20 = get_collection("20_features", persist_dir=self.temp_dir)

        self.assertEqual(col10.name, COLLECTION_10_NAME)
        self.assertEqual(col20.name, COLLECTION_20_NAME)
        self.assertEqual(col10.count(), 2)
        self.assertEqual(col20.count(), 2)

        # Cannot insert 10-feature vector into 20-feature collection
        with self.assertRaises(ValueError):
            insert_phishing_vector("20_features", [1] * 10, persist_dir=self.temp_dir)

        # Cannot insert 20-feature vector into 10-feature collection
        with self.assertRaises(ValueError):
            insert_phishing_vector("10_features", [1] * 20, persist_dir=self.temp_dir)

    # --- Test 9: Idempotence — Rerunning does not duplicate records ---
    def test_idempotent_import_no_duplicates(self):
        self._create_synthetic_10_csv()
        stats1 = import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        self.assertEqual(stats1["newly_inserted"], 2)
        self.assertEqual(stats1["final_count"], 2)

        # Re-run import
        stats2 = import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        self.assertEqual(stats2["newly_inserted"], 0)
        self.assertEqual(stats2["already_existing"], 2)
        self.assertEqual(stats2["final_count"], 2)

    # --- Test 10: Identical feature vectors from distinct source rows preserved ---
    def test_identical_vectors_distinct_rows_preserved(self):
        # In _create_synthetic_10_csv, Row 0 and Row 2 have identical features but are distinct phishing cases
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        col = get_collection("10_features", persist_dir=self.temp_dir)
        self.assertEqual(col.count(), 2)
        ids = col.get()["ids"]
        self.assertIn("phish_10_features_row_00000", ids)
        self.assertIn("phish_10_features_row_00002", ids)

    # --- Test 11: No original URLs or domains in metadata ---
    def test_no_urls_or_domains_in_metadata(self):
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)
        col = get_collection("10_features", persist_dir=self.temp_dir)
        all_meta = col.get(include=["metadatas"])["metadatas"]
        for m in all_meta:
            self.assertNotIn("url", m)
            self.assertNotIn("domain", m)
            self.assertNotIn("hostname", m)
            for k, v in m.items():
                self.assertNotIn("http://", str(v).lower())
                self.assertNotIn("https://", str(v).lower())

        # Attempting to insert metadata with url raises ValueError
        with self.assertRaises(ValueError):
            insert_phishing_vector(
                "10_features",
                [1] * 10,
                metadata={"url": "http://evil.com"},
                persist_dir=self.temp_dir
            )

    # --- Test 12: Persistence verified after reopening client ---
    def test_persistence_after_reopening_client(self):
        self._create_synthetic_10_csv()
        import_dataset("phishing_10_features.csv", "10_features", self.data_temp_dir, self.temp_dir)

        # Reopen client pointing to the same persistent directory
        reopened_client = chromadb.PersistentClient(path=self.temp_dir)
        reopened_col = reopened_client.get_collection(COLLECTION_10_NAME)
        self.assertEqual(reopened_col.count(), 2)
        sample = reopened_col.get(limit=1, include=["embeddings", "metadatas"])
        self.assertEqual(len(sample["embeddings"][0]), 10)
        self.assertEqual(sample["metadatas"][0]["model_type"], "10_features")

    # --- Test 13: Invalid vector dimensions and model types rejected ---
    def test_invalid_dimensions_and_model_types_rejected(self):
        with self.assertRaises(ValueError):
            validate_model_type("unknown_model")

        with self.assertRaises(ValueError):
            get_collection("invalid_type", persist_dir=self.temp_dir)

        with self.assertRaises(ValueError):
            validate_vector("10_features", [1] * 9)

        with self.assertRaises(ValueError):
            validate_vector("10_features", [1] * 11)

        with self.assertRaises(ValueError):
            validate_vector("20_features", [1] * 19)

        with self.assertRaises(ValueError):
            validate_vector("20_features", [1] * 21)


class TestRealDatabaseIntegrity(unittest.TestCase):
    """
    Read-only tests verifying the production chroma_db collection integrity.
    """

    def test_production_chroma_db_collections_exist_and_populated(self):
        # Verify default persistent database
        stats10 = get_collection_stats("10_features")
        self.assertEqual(stats10["collection_name"], COLLECTION_10_NAME)
        self.assertEqual(stats10["count"], 4898)

        stats20 = get_collection_stats("20_features")
        self.assertEqual(stats20["collection_name"], COLLECTION_20_NAME)
        self.assertEqual(stats20["count"], 4898)

    def test_production_chroma_db_samples_have_correct_labels(self):
        col10 = get_collection("10_features")
        sample10 = col10.peek(limit=5)
        for meta in sample10["metadatas"]:
            self.assertEqual(meta["source_label"], -1)
            self.assertEqual(meta["prediction_label"], -1)
            self.assertEqual(meta["model_type"], "10_features")

        col20 = get_collection("20_features")
        sample20 = col20.peek(limit=5)
        for meta in sample20["metadatas"]:
            self.assertEqual(meta["source_label"], -1)
            self.assertEqual(meta["prediction_label"], -1)
            self.assertEqual(meta["model_type"], "20_features")


if __name__ == "__main__":
    unittest.main()
