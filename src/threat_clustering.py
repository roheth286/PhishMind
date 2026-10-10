"""
Threat Intelligence Clustering Module.

Performs unsupervised clustering discovery and profiling on historical phishing
feature vectors stored in ChromaDB collections.

Key requirements addressed:
- Clustering discovery on discrete coordinate space.
- Well-documented algorithm selection (KMeans with Euclidean distance).
- Explicit handling of discrete categorical dimensions (-1, 0, 1).
- Reproducible random state (default random_state=42).
- Edge-case resilience (empty dataset, small dataset < k, all identical vectors).
- Detailed cluster profiles: size, percentage, noise count, distinct patterns,
  feature value frequencies, percentages, dominant values, and uniformity.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

from src.threat_vector_db import (
    FEATURES_10,
    FEATURES_20,
    validate_model_type,
)


def discover_clusters(
    model_type: str,
    vectors: List[List[int]],
    record_ids: Optional[List[str]] = None,
    n_clusters: Optional[int] = None,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Discover clusters among the provided feature vectors using KMeans.

    Rationale:
    In discrete ternary feature space (-1, 0, 1), standard distance-based clustering
    must avoid chaining artifacts (common with single/average linkage hierarchical clustering)
    and severe fragmentation/noise classification of identical patterns (common with density
    clustering like DBSCAN without custom eps tuning). KMeans with Euclidean distance partitions
    ternary coordinates cleanly into compact, balanced, and interpretable groupings representing
    archetypal phishing campaigns. Centroids indicate average feature orientation across the cluster.

    Args:
        model_type: "10_features" or "20_features"
        vectors: List of integer feature vectors
        record_ids: Optional list of record IDs corresponding to vectors
        n_clusters: Optional fixed number of clusters (k). If None, automatic selection
                    evaluates k in [3, 4, 5, 6] via silhouette score.
        random_state: Seed for reproducibility (default 42).

    Returns:
        Dict containing:
            - model_type
            - algorithm: "KMeans"
            - distance_metric: "euclidean"
            - random_state
            - n_clusters
            - labels: List[int] cluster assignment for each record
            - centroids: List[List[float]]
            - inertia: float
            - silhouette_score: Optional[float]
            - record_ids: Optional[List[str]]
            - status: "success" or edge case reason ("empty", "insufficient_samples", "all_identical")
            - rationale: String explanation of algorithm and parameters
    """
    validate_model_type(model_type)
    n_samples = len(vectors)

    if record_ids is None:
        record_ids = [f"rec_{i}" for i in range(n_samples)]

    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    n_dim = len(expected_features)

    # Edge Case 1: Empty dataset
    if n_samples == 0:
        return {
            "model_type": model_type,
            "algorithm": "KMeans",
            "distance_metric": "euclidean",
            "random_state": random_state,
            "n_clusters": 0,
            "labels": [],
            "centroids": [],
            "inertia": 0.0,
            "silhouette_score": None,
            "record_ids": [],
            "status": "empty_dataset",
            "rationale": "No samples available for clustering.",
        }

    X = np.array(vectors, dtype=float)

    # Edge Case 2: Very small dataset (1 or 2 samples)
    if n_samples < 3:
        k = max(1, n_samples)
        kmeans = KMeans(n_clusters=k, random_state=random_state, n_init=10)
        labels = kmeans.fit_predict(X).tolist()
        return {
            "model_type": model_type,
            "algorithm": "KMeans",
            "distance_metric": "euclidean",
            "random_state": random_state,
            "n_clusters": k,
            "labels": labels,
            "centroids": [c.tolist() for c in kmeans.cluster_centers_],
            "inertia": float(kmeans.inertia_),
            "silhouette_score": None,
            "record_ids": record_ids,
            "status": "insufficient_samples",
            "rationale": f"Fewer than 3 samples ({n_samples}); defaulted to k={k}.",
        }

    # Edge Case 3: All vectors identical
    unique_rows = np.unique(X, axis=0)
    if len(unique_rows) == 1:
        return {
            "model_type": model_type,
            "algorithm": "KMeans",
            "distance_metric": "euclidean",
            "random_state": random_state,
            "n_clusters": 1,
            "labels": [0] * n_samples,
            "centroids": [unique_rows[0].tolist()],
            "inertia": 0.0,
            "silhouette_score": None,
            "record_ids": record_ids,
            "status": "all_identical",
            "rationale": "All vectors in dataset are identical. Single cluster formed.",
        }

    # Determine k
    best_k = n_clusters
    best_score = -1.0
    sil_score: Optional[float] = None

    if best_k is None:
        candidate_ks = [k for k in [3, 4, 5, 6] if k < n_samples and k <= len(unique_rows)]
        if not candidate_ks:
            candidate_ks = [min(len(unique_rows), 2)]

        best_k = candidate_ks[0]
        # Evaluate silhouette scores
        for k in candidate_ks:
            km = KMeans(n_clusters=k, random_state=random_state, n_init=10)
            candidate_labels = km.fit_predict(X)
            # Silhouette requires at least 2 distinct clusters and distinct points
            if len(np.unique(candidate_labels)) > 1:
                score = float(silhouette_score(X, candidate_labels))
                if score > best_score:
                    best_score = score
                    best_k = k

    # Ensure k does not exceed number of unique samples or total samples
    max_possible_k = min(n_samples, len(unique_rows))
    effective_k = min(best_k, max_possible_k)
    effective_k = max(1, effective_k)

    kmeans = KMeans(n_clusters=effective_k, random_state=random_state, n_init=10)
    labels = kmeans.fit_predict(X).tolist()
    inertia = float(kmeans.inertia_)
    centroids = [c.tolist() for c in kmeans.cluster_centers_]

    if effective_k > 1 and len(np.unique(labels)) > 1:
        try:
            sil_score = float(silhouette_score(X, labels))
        except Exception:
            sil_score = None
    else:
        sil_score = None

    rationale_str = (
        f"KMeans clustering with Euclidean distance in discrete ternary space (-1, 0, 1) "
        f"using {effective_k} clusters, n_init=10, random_state={random_state}. "
        f"Provides partition stability, avoids chaining artifacts, and yields interpretable "
        f"threat archetype centroids."
    )

    return {
        "model_type": model_type,
        "algorithm": "KMeans",
        "distance_metric": "euclidean",
        "random_state": random_state,
        "n_clusters": effective_k,
        "labels": labels,
        "centroids": centroids,
        "inertia": round(inertia, 4),
        "silhouette_score": round(sil_score, 4) if sil_score is not None else None,
        "record_ids": record_ids,
        "status": "success",
        "rationale": rationale_str,
    }


def analyze_cluster_sizes(
    clustering_result: Dict[str, Any],
    vectors: List[List[int]],
) -> List[Dict[str, Any]]:
    """
    Analyze cluster sizes, proportions, noise points, and distinct vector patterns.

    Returns:
        List of cluster size analysis dictionaries sorted by cluster ID.
    """
    labels = clustering_result.get("labels", [])
    total_records = len(labels)
    if total_records == 0:
        return []

    n_clusters = clustering_result.get("n_clusters", 0)

    # Group vectors by cluster label
    cluster_vectors: Dict[int, List[Tuple[int, ...]]] = {c: [] for c in range(n_clusters)}
    for idx, cluster_id in enumerate(labels):
        if cluster_id in cluster_vectors and idx < len(vectors):
            cluster_vectors[cluster_id].append(tuple(vectors[idx]))

    size_analysis: List[Dict[str, Any]] = []
    for cluster_id in range(n_clusters):
        vecs = cluster_vectors.get(cluster_id, [])
        count = len(vecs)
        pct = round((count / total_records) * 100.0, 4) if total_records > 0 else 0.0
        distinct_patterns = len(set(vecs))

        size_analysis.append({
            "cluster_id": cluster_id,
            "member_count": count,
            "percentage": pct,
            "noise_count": 0,  # KMeans assigns every sample to a cluster; 0 unassigned noise
            "distinct_vector_patterns_count": distinct_patterns,
        })

    return size_analysis


def profile_clusters(
    clustering_result: Dict[str, Any],
    vectors: List[List[int]],
    model_type: str,
) -> Dict[str, Any]:
    """
    Produce comprehensive feature profiles for each cluster:
    - Feature value frequencies (-1, 0, 1) and percentages.
    - Dominant value(s).
    - Uniformity flag (True if 100% of samples in cluster share the same value for that feature).
    - Centroid coordinates.
    """
    validate_model_type(model_type)
    expected_features = FEATURES_10 if model_type == "10_features" else FEATURES_20
    labels = clustering_result.get("labels", [])
    n_clusters = clustering_result.get("n_clusters", 0)
    centroids = clustering_result.get("centroids", [])

    profiles: Dict[str, Any] = {}

    if len(vectors) == 0 or len(labels) == 0:
        return profiles

    # Group vectors by cluster
    grouped: Dict[int, List[List[int]]] = {c: [] for c in range(n_clusters)}
    for idx, c in enumerate(labels):
        if c in grouped and idx < len(vectors):
            grouped[c].append(vectors[idx])

    for cluster_id in range(n_clusters):
        c_vecs = grouped.get(cluster_id, [])
        c_size = len(c_vecs)
        c_centroid = centroids[cluster_id] if cluster_id < len(centroids) else []

        feature_profiles: Dict[str, Any] = {}

        for f_idx, feat_name in enumerate(expected_features):
            val_counts = {-1: 0, 0: 0, 1: 0}
            for v in c_vecs:
                if f_idx < len(v):
                    val = v[f_idx]
                    if val in val_counts:
                        val_counts[val] += 1
                    else:
                        val_counts[val] = 1

            val_percentages = {}
            for val, cnt in val_counts.items():
                val_percentages[str(val)] = round((cnt / c_size * 100.0), 4) if c_size > 0 else 0.0

            # Find dominant value(s)
            max_cnt = -1
            dominant_vals: List[int] = []
            for val in [-1, 0, 1]:
                cnt = val_counts.get(val, 0)
                if cnt > max_cnt:
                    max_cnt = cnt
                    dominant_vals = [val]
                elif cnt == max_cnt and max_cnt > 0:
                    dominant_vals.append(val)

            # Uniformity check: exactly one value represents 100% of cluster members
            is_uniform = (max_cnt == c_size and c_size > 0)

            feature_profiles[feat_name] = {
                "counts": {str(k): v for k, v in val_counts.items()},
                "percentages": val_percentages,
                "dominant_values": dominant_vals,
                "is_uniform": is_uniform,
                "centroid_value": round(c_centroid[f_idx], 4) if f_idx < len(c_centroid) else None,
            }

        profiles[f"cluster_{cluster_id}"] = {
            "cluster_id": cluster_id,
            "member_count": c_size,
            "percentage_of_total": round((c_size / len(vectors) * 100.0), 4) if len(vectors) > 0 else 0.0,
            "features": feature_profiles,
        }

    return profiles
