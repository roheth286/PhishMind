"""
Tests for threat intelligence clustering discovery and profiling.
"""

import pytest
from src.threat_clustering import (
    analyze_cluster_sizes,
    discover_clusters,
    profile_clusters,
)


def test_discover_clusters_empty_dataset():
    res = discover_clusters("10_features", [])
    assert res["status"] == "empty_dataset"
    assert res["n_clusters"] == 0
    assert res["labels"] == []


def test_discover_clusters_insufficient_samples():
    vecs = [[-1, 1, 1, 1, -1, 1, -1, 1, 1, 0], [1, 1, -1, 1, -1, 1, -1, 1, 1, 0]]
    res = discover_clusters("10_features", vecs)
    assert res["status"] == "insufficient_samples"
    assert res["n_clusters"] == 2
    assert len(res["labels"]) == 2


def test_discover_clusters_all_identical():
    sample = [-1, 1, 1, 1, -1, 1, -1, 1, 1, 0]
    vecs = [sample.copy() for _ in range(10)]
    res = discover_clusters("10_features", vecs)
    assert res["status"] == "all_identical"
    assert res["n_clusters"] == 1
    assert all(l == 0 for l in res["labels"])


def test_discover_clusters_and_profiling_normal():
    # Synthetic dataset with 2 distinct groupings
    group_a = [[-1, -1, -1, -1, -1, -1, -1, -1, -1, -1] for _ in range(20)]
    group_b = [[1, 1, 1, 1, 1, 1, 1, 1, 1, 0] for _ in range(20)]
    vecs = group_a + group_b

    res = discover_clusters("10_features", vecs, n_clusters=2, random_state=42)
    assert res["status"] == "success"
    assert res["n_clusters"] == 2
    assert len(res["labels"]) == 40
    assert res["silhouette_score"] is not None
    assert res["silhouette_score"] > 0.8

    # Size analysis
    sizes = analyze_cluster_sizes(res, vecs)
    assert len(sizes) == 2
    assert sizes[0]["member_count"] + sizes[1]["member_count"] == 40
    assert all(s["noise_count"] == 0 for s in sizes)

    # Profiling
    profiles = profile_clusters(res, vecs, "10_features")
    assert len(profiles) == 2
    # Verify uniformity detection on group with all -1
    for c_id, prof in profiles.items():
        assert prof["member_count"] == 20
        # In this synthetic dataset, all features are perfectly uniform
        for f_name, f_info in prof["features"].items():
            assert f_info["is_uniform"] is True
