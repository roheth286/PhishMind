"""
Recommendation Configuration Module.

Defines centralized, configurable thresholds and settings for the 20 Threat Intelligence
Recommendation Rules. All thresholds can be modified at runtime or loaded from
custom settings without changing rule evaluation logic.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class RecommendationConfig:
    """
    Centralized configuration for threat recommendation evaluation.
    """
    config_version: str = "1.0.0"

    # Global Dataset Requirements
    min_collection_records: int = 100

    # Rule 1: Shortened URL Protection (Shortining_Service == -1)
    rule_1_min_count: int = 50
    rule_1_min_percentage: float = 5.0

    # Rule 2: Suspicious IP-Address Links (having_IP_Address == -1)
    rule_2_min_count: int = 50
    rule_2_min_percentage: float = 10.0

    # Rule 3: Lookalike Domain Protection (Prefix_Suffix == -1)
    rule_3_min_count: int = 100
    rule_3_min_percentage: float = 20.0

    # Rule 4: Suspicious Subdomain Review (having_Sub_Domain in {-1, 0})
    rule_4_min_count: int = 100
    rule_4_min_percentage: float = 20.0

    # Rule 5: HTTPS and Certificate Validation (SSLfinal_State in {-1, 0} or HTTPS_token in {-1, 1})
    rule_5_ssl_min_count: int = 100
    rule_5_ssl_min_percentage: float = 20.0

    # Rule 6: URL Parsing and Normalization (URL_Length in {-1, 0})
    rule_6_min_count: int = 100
    rule_6_min_percentage: float = 20.0

    # Rule 7: External Link Inspection (URL_of_Anchor in {-1, 0} or Request_URL == -1 or Prefix_Suffix == -1)
    rule_7_min_count: int = 100
    rule_7_min_percentage: float = 20.0

    # Rule 8: Attachment and Link Defense (Composite prevalence across link features)
    rule_8_min_composite_count: int = 100
    rule_8_min_composite_percentage: float = 25.0

    # Rule 9: Sender Authentication (Motivating threshold across core spoofing-related signals)
    rule_9_min_count: int = 100
    rule_9_min_percentage: float = 15.0

    # Rule 10: Domain Reputation Checks (Prefix_Suffix or Subdomain or Co-occurrence evidence)
    rule_10_min_count: int = 100
    rule_10_min_percentage: float = 20.0

    # Rule 11: Outbound Web Access Controls (port == -1)
    rule_11_min_count: int = 50
    rule_11_min_percentage: float = 5.0

    # Rule 12: Security Awareness Training (Dataset scale threshold)
    rule_12_min_dataset_size: int = 500

    # Rule 13: Lookalike-Domain Monitoring (Prefix_Suffix == -1)
    rule_13_min_count: int = 100
    rule_13_min_percentage: float = 25.0

    # Rule 14: Safe URL Detonation (High prevalence of multi-vector phishing signals or dominant cluster)
    rule_14_min_cluster_share_pct: float = 20.0

    # Rule 15: Web Gateway Policy Review (Multiple URL risk signals meeting threshold)
    rule_15_min_qualifying_signals: int = 2
    rule_15_signal_min_pct: float = 20.0

    # Rule 16: Cluster-Driven Detection Rules
    rule_16_min_cluster_size: int = 200
    rule_16_min_cluster_share_pct: float = 10.0

    # Rule 17: Rare-Pattern Investigation
    rule_17_min_rare_patterns: int = 5
    rule_17_max_rarity_count: int = 2

    # Rule 18: Layered Phishing Defenses
    rule_18_min_distinct_categories: int = 2
    rule_18_category_min_pct: float = 20.0

    # Rule 19: Security Control Effectiveness Review (Time-Series)
    rule_19_min_time_windows: int = 2
    rule_19_min_trend_records: int = 100

    # Rule 20: Prioritize the Strongest Evidence
    rule_20_min_top_signal_pct: float = 50.0

    # Output Controls
    max_active_recommendations: int = 20
    deduplication_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_RECOMMENDATION_CONFIG = RecommendationConfig()
