"""
Recommendation Rules Registry Module.

Defines all 20 transparent, rule-based recommendation evaluation functions.
Each rule defines:
- Stable rule ID and recommendation ID
- Category and business-facing title
- Predefined recommendation text
- Strict evidence extraction and threshold evaluation
- Documented priority classification and rationale
- Transparent limitations acknowledging observational data constraints
"""

from typing import Any, Dict, List, Optional
from src.recommendation_config import RecommendationConfig


def _build_rec_dict(
    rule_id: str,
    model_type: str,
    title: str,
    category: str,
    recommendation: str,
    status: str,
    priority: str,
    priority_reason: str,
    trigger_reason: str,
    evidence: Dict[str, Any],
    thresholds: Dict[str, Any],
    limitations: List[str],
) -> Dict[str, Any]:
    """Helper to assemble a consistent recommendation output dictionary."""
    return {
        "recommendation_id": f"{rule_id}_{model_type}",
        "rule_id": rule_id,
        "model_type": model_type,
        "title": title,
        "category": category,
        "recommendation": recommendation,
        "status": status,
        "priority": priority,
        "priority_reason": priority_reason,
        "trigger_reason": trigger_reason,
        "evidence": evidence,
        "thresholds": thresholds,
        "limitations": limitations,
    }


# ==============================================================================
# RULE 1: Shortened URL Protection
# ==============================================================================
def evaluate_rule_1_shortened_url(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_01_SHORTENED_URL"
    title = "Shortened URL protection"
    category = "Email & web security"
    rec_text = (
        "Consider strengthening email and web security controls to expand shortened links "
        "safely, inspect their final destinations, and flag suspicious redirects."
    )
    limitations = [
        "Describes historical phishing feature distributions in the stored dataset.",
        "Does not assume every shortened URL is malicious.",
        "Does not establish causation or confirm a particular attack campaign.",
    ]
    thresholds = {
        "minimum_count": config.rule_1_min_count,
        "minimum_percentage": config.rule_1_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "Shortining_Service" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Insufficient feature statistics or record denominator.",
            trigger_reason="Shortening service feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    short_stats = feature_stats["Shortining_Service"]
    counts = short_stats.get("counts", {})
    percentages = short_stats.get("percentages", {})

    count_neg1 = counts.get("-1", 0)
    pct_neg1 = percentages.get("-1", 0.0)

    evidence = {
        "feature": "Shortining_Service",
        "feature_value": -1,
        "count": count_neg1,
        "denominator": denominator,
        "percentage": pct_neg1,
        "collection": model_type,
    }

    if count_neg1 >= config.rule_1_min_count and pct_neg1 >= config.rule_1_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="medium",
            priority_reason="Measured prevalence of shortened URLs in phishing dataset meets review threshold.",
            trigger_reason=(
                f"Shortened URL indicator ('Shortining_Service == -1') observed in {count_neg1} "
                f"of {denominator} phishing cases ({pct_neg1:.2f}%), exceeding thresholds "
                f"({config.rule_1_min_count} count, {config.rule_1_min_percentage}%)."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Measured prevalence does not meet threshold.",
        trigger_reason=f"Observed count ({count_neg1}) or percentage ({pct_neg1:.2f}%) below configured threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 2: Suspicious IP-Address Links
# ==============================================================================
def evaluate_rule_2_ip_address_links(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_02_IP_ADDRESS_LINKS"
    title = "Suspicious IP-address links"
    category = "Web security"
    rec_text = (
        "Consider configuring web gateways and email filters to flag links that use raw IP addresses "
        "where legitimate business traffic normally uses approved domain names."
    )
    limitations = [
        "Describes historical phishing feature distributions in the stored dataset.",
        "Does not claim that all IP-address URLs are malicious.",
        "Does not inspect live organizational gateway configurations.",
    ]
    thresholds = {
        "minimum_count": config.rule_2_min_count,
        "minimum_percentage": config.rule_2_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "having_IP_Address" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Missing IP address feature statistics.",
            trigger_reason="IP address feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    ip_stats = feature_stats["having_IP_Address"]
    count_neg1 = ip_stats.get("counts", {}).get("-1", 0)
    pct_neg1 = ip_stats.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "having_IP_Address",
        "feature_value": -1,
        "count": count_neg1,
        "denominator": denominator,
        "percentage": pct_neg1,
        "collection": model_type,
    }

    if count_neg1 >= config.rule_2_min_count and pct_neg1 >= config.rule_2_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Substantial proportion of phishing samples utilize raw IP addresses instead of domains.",
            trigger_reason=(
                f"Raw IP address links ('having_IP_Address == -1') observed in {count_neg1} "
                f"of {denominator} cases ({pct_neg1:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="IP address link prevalence below threshold.",
        trigger_reason=f"Observed count ({count_neg1}) or percentage ({pct_neg1:.2f}%) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 3: Lookalike Domain Protection
# ==============================================================================
def evaluate_rule_3_lookalike_domain(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_03_LOOKALIKE_DOMAIN"
    title = "Lookalike domain protection"
    category = "Domain security"
    rec_text = (
        "Consider deploying domain-impersonation checks that compare external domains with "
        "your organization's domains and trusted business partners."
    )
    limitations = [
        "The prefix/suffix feature indicates hyphenation syntax; it is not proof that a domain impersonates a specific brand.",
        "Phrase findings as a signal worth reviewing rather than confirmed impersonation.",
    ]
    thresholds = {
        "minimum_count": config.rule_3_min_count,
        "minimum_percentage": config.rule_3_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "Prefix_Suffix" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Prefix/suffix feature statistics unavailable.",
            trigger_reason="Prefix/suffix feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    ps_stats = feature_stats["Prefix_Suffix"]
    count_neg1 = ps_stats.get("counts", {}).get("-1", 0)
    pct_neg1 = ps_stats.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "Prefix_Suffix",
        "feature_value": -1,
        "count": count_neg1,
        "denominator": denominator,
        "percentage": pct_neg1,
        "collection": model_type,
    }

    if count_neg1 >= config.rule_3_min_count and pct_neg1 >= config.rule_3_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Extremely prevalent hyphenated domain structure observed across phishing cases.",
            trigger_reason=(
                f"Prefix/suffix hyphenation ('Prefix_Suffix == -1') observed in {count_neg1} "
                f"of {denominator} cases ({pct_neg1:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Prefix/suffix signal below threshold.",
        trigger_reason=f"Observed count ({count_neg1}) or percentage ({pct_neg1:.2f}%) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 4: Suspicious Subdomain Review
# ==============================================================================
def evaluate_rule_4_subdomain_review(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_04_SUBDOMAIN_REVIEW"
    title = "Suspicious subdomain review"
    category = "Domain security"
    rec_text = (
        "Consider reviewing URL inspection policies for unusually nested subdomains and "
        "destinations designed to make untrusted websites appear legitimate."
    )
    limitations = [
        "Subdomain feature encoding reflects dot count in host portion.",
        "Does not claim that the feature alone identifies malicious subdomains.",
    ]
    thresholds = {
        "minimum_count": config.rule_4_min_count,
        "minimum_percentage": config.rule_4_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "having_Sub_Domain" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Subdomain statistics unavailable.",
            trigger_reason="Subdomain statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    sub_stats = feature_stats["having_Sub_Domain"]
    # Suspicious subdomains in dataset include multi-nested (-1: phishing, 0: suspicious/moderate)
    count_suspicious = sub_stats.get("counts", {}).get("-1", 0) + sub_stats.get("counts", {}).get("0", 0)
    pct_suspicious = round((count_suspicious / denominator * 100.0), 4)

    evidence = {
        "feature": "having_Sub_Domain",
        "evaluated_values": [-1, 0],
        "count": count_suspicious,
        "denominator": denominator,
        "percentage": pct_suspicious,
        "collection": model_type,
    }

    if count_suspicious >= config.rule_4_min_count and pct_suspicious >= config.rule_4_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="High prevalence of complex/multi-level subdomain nesting in phishing samples.",
            trigger_reason=(
                f"Suspicious subdomain nesting observed in {count_suspicious} of {denominator} "
                f"cases ({pct_suspicious:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Subdomain nesting below threshold.",
        trigger_reason=f"Observed count ({count_suspicious}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 5: HTTPS and Certificate Validation
# ==============================================================================
def evaluate_rule_5_https_validation(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_05_HTTPS_VALIDATION"
    title = "HTTPS and certificate validation"
    category = "Web security"
    rec_text = (
        "Consider ensuring that web security controls validate TLS certificates and the actual destination "
        "hostname, rather than treating the presence of HTTPS as proof that a website is trustworthy."
    )
    limitations = [
        "The HTTPS_token feature (URL token) and SSLfinal_State feature (certificate trust) are not interchangeable.",
        "Does not infer real certificate validity from a URL string token alone.",
    ]
    thresholds = {
        "minimum_count": config.rule_5_ssl_min_count,
        "minimum_percentage": config.rule_5_ssl_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "SSLfinal_State" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="SSLfinal_State feature statistics unavailable.",
            trigger_reason="SSLfinal_State feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    ssl_stats = feature_stats["SSLfinal_State"]
    # SSLfinal_State == -1 indicates untrusted, self-signed, or missing valid CA certificate
    count_ssl_neg1 = ssl_stats.get("counts", {}).get("-1", 0)
    pct_ssl_neg1 = ssl_stats.get("percentages", {}).get("-1", 0.0)

    https_token_stats = feature_stats.get("HTTPS_token", {})
    token_1_pct = https_token_stats.get("percentages", {}).get("1", 0.0)

    evidence = {
        "feature_primary": "SSLfinal_State",
        "feature_primary_value": -1,
        "ssl_untrusted_count": count_ssl_neg1,
        "denominator": denominator,
        "ssl_untrusted_percentage": pct_ssl_neg1,
        "https_token_legitimate_syntax_percentage": token_1_pct,
        "collection": model_type,
    }

    if count_ssl_neg1 >= config.rule_5_ssl_min_count and pct_ssl_neg1 >= config.rule_5_ssl_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Untrusted or invalid TLS certificates are prominent in phishing data.",
            trigger_reason=(
                f"Untrusted TLS state ('SSLfinal_State == -1') observed in {count_ssl_neg1} "
                f"of {denominator} cases ({pct_ssl_neg1:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Untrusted SSL prevalence below threshold.",
        trigger_reason=f"Observed count ({count_ssl_neg1}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 6: URL Parsing and Normalization
# ==============================================================================
def evaluate_rule_6_url_normalization(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_06_URL_NORMALIZATION"
    title = "URL parsing and normalization"
    category = "Email & web security"
    rec_text = (
        "Consider strengthening URL parsing and normalization in email and web filters so that "
        "unusually long or obfuscated links receive additional inspection."
    )
    limitations = [
        "URL length categorization is based on static character count thresholds.",
        "Does not label a URL as obfuscated solely because it is long.",
    ]
    thresholds = {
        "minimum_count": config.rule_6_min_count,
        "minimum_percentage": config.rule_6_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "URL_Length" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="URL_Length feature statistics unavailable.",
            trigger_reason="URL_Length feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    url_stats = feature_stats["URL_Length"]
    count_neg1 = url_stats.get("counts", {}).get("-1", 0)
    pct_neg1 = url_stats.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "URL_Length",
        "feature_value": -1,
        "count": count_neg1,
        "denominator": denominator,
        "percentage": pct_neg1,
        "collection": model_type,
    }

    if count_neg1 >= config.rule_6_min_count and pct_neg1 >= config.rule_6_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="A heavy majority of phishing samples exhibit long, complex URL strings (>75 chars).",
            trigger_reason=(
                f"Long URL indicator ('URL_Length == -1') observed in {count_neg1} "
                f"of {denominator} cases ({pct_neg1:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="URL length indicator below threshold.",
        trigger_reason=f"Observed count ({count_neg1}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 7: External Link Inspection
# ==============================================================================
def evaluate_rule_7_external_link_inspection(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_07_EXTERNAL_LINK_INSPECTION"
    title = "External link inspection"
    category = "Email security"
    rec_text = (
        "Consider requiring security inspection of links in incoming emails before users visit external destinations, "
        "especially when the destination is unfamiliar."
    )
    limitations = [
        "Does not claim that the database contains email messages or sender identities.",
        "Reflects recurring external link structural features identified in historical phishing data.",
    ]
    thresholds = {
        "minimum_count": config.rule_7_min_count,
        "minimum_percentage": config.rule_7_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Feature statistics unavailable.",
            trigger_reason="Feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    # In 20-features, evaluate URL_of_Anchor or Request_URL; in 10-features, evaluate Prefix_Suffix
    if model_type == "20_features" and "URL_of_Anchor" in feature_stats:
        anchor_stats = feature_stats["URL_of_Anchor"]
        eval_count = anchor_stats.get("counts", {}).get("-1", 0)
        eval_pct = anchor_stats.get("percentages", {}).get("-1", 0.0)
        eval_feature = "URL_of_Anchor"
    else:
        ps_stats = feature_stats.get("Prefix_Suffix", {})
        eval_count = ps_stats.get("counts", {}).get("-1", 0)
        eval_pct = ps_stats.get("percentages", {}).get("-1", 0.0)
        eval_feature = "Prefix_Suffix"

    evidence = {
        "evaluated_feature": eval_feature,
        "feature_value": -1,
        "count": eval_count,
        "denominator": denominator,
        "percentage": eval_pct,
        "collection": model_type,
    }

    if eval_count >= config.rule_7_min_count and eval_pct >= config.rule_7_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="High prevalence of deceptive external link structural indicators.",
            trigger_reason=(
                f"Suspicious external link feature ('{eval_feature} == -1') observed in {eval_count} "
                f"of {denominator} cases ({eval_pct:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="External link indicator below threshold.",
        trigger_reason=f"Observed count ({eval_count}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 8: Attachment and Link Defense
# ==============================================================================
def evaluate_rule_8_attachment_link_defense(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_08_ATTACHMENT_LINK_DEFENSE"
    title = "Attachment and link defense"
    category = "Email security"
    rec_text = (
        "Consider combining email link inspection with attachment scanning, sender authentication checks, "
        "and clear reporting procedures for suspicious messages."
    )
    limitations = [
        "This is a general defensive recommendation.",
        "URL feature vectors do not establish that malicious attachments were present.",
    ]
    thresholds = {
        "minimum_composite_count": config.rule_8_min_composite_count,
        "minimum_composite_percentage": config.rule_8_min_composite_percentage,
    }

    top_signals = analytics_bundle.get("top_signals", [])
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not top_signals or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Top signals evidence unavailable.",
            trigger_reason="Top signals evidence unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    # Trigger if multiple high-frequency phishing signals justify a combined defense
    qualifying_signals = [s for s in top_signals if s.get("percentage", 0.0) >= config.rule_8_min_composite_percentage]

    evidence = {
        "qualifying_signals_count": len(qualifying_signals),
        "qualifying_signals_sample": [s["signal_name"] for s in qualifying_signals[:5]],
        "denominator": denominator,
        "collection": model_type,
    }

    if len(qualifying_signals) >= 3 and denominator >= config.rule_8_min_composite_count:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="medium",
            priority_reason="High variety and frequency of persistent link attack patterns.",
            trigger_reason=(
                f"Identified {len(qualifying_signals)} distinct feature signals exceeding "
                f"{config.rule_8_min_composite_percentage}% support across {denominator} phishing records."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Fewer than 3 signals met composite threshold.",
        trigger_reason="Fewer than 3 signals met composite threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 9: Sender Authentication
# ==============================================================================
def evaluate_rule_9_sender_authentication(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_09_SENDER_AUTHENTICATION"
    title = "Sender authentication"
    category = "Email security"
    rec_text = (
        "Consider reviewing SPF, DKIM, and DMARC configurations for your organization's domains "
        "and monitoring failures that could indicate spoofing attempts."
    )
    limitations = [
        "Dataset evidence motivates a control review rather than proving a sender-authentication failure.",
        "The engine does not inspect an organization's SPF, DKIM, or DMARC records.",
    ]
    thresholds = {
        "minimum_count": config.rule_9_min_count,
        "minimum_percentage": config.rule_9_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    # In 20-features, evaluate Submitting_to_email; in 10-features evaluate domain prefix/suffix
    eval_feat = "Submitting_to_email" if (model_type == "20_features" and "Submitting_to_email" in feature_stats) else "Prefix_Suffix"
    
    if not feature_stats or eval_feat not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Feature statistics unavailable.",
            trigger_reason="Feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    feat_info = feature_stats[eval_feat]
    cnt = feat_info.get("counts", {}).get("-1", 0)
    pct = feat_info.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "motivating_feature": eval_feat,
        "feature_value": -1,
        "count": cnt,
        "denominator": denominator,
        "percentage": pct,
        "collection": model_type,
    }

    if cnt >= config.rule_9_min_count and pct >= config.rule_9_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="medium",
            priority_reason="Substantial domain and email-related threat indicators motivate authentication hardening.",
            trigger_reason=(
                f"Motivating signal '{eval_feat} == -1' observed in {cnt} of {denominator} "
                f"cases ({pct:.2f}%), indicating widespread spoofing/impersonation tactics."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Motivating signal below threshold.",
        trigger_reason=f"Observed count ({cnt}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 10: Domain Reputation Checks
# ==============================================================================
def evaluate_rule_10_domain_reputation(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_10_DOMAIN_REPUTATION"
    title = "Domain reputation checks"
    category = "Threat intelligence"
    rec_text = (
        "Consider integrating domain reputation and threat-intelligence checks into email and web gateways, "
        "with safeguards to minimize false positives."
    )
    limitations = [
        "Based on observed recurring domain-level signals in historical phishing vectors.",
        "Does not make external queries to third-party domain reputation APIs.",
    ]
    thresholds = {
        "minimum_count": config.rule_10_min_count,
        "minimum_percentage": config.rule_10_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "Prefix_Suffix" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Prefix_Suffix feature statistics unavailable.",
            trigger_reason="Prefix_Suffix feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    ps_stats = feature_stats["Prefix_Suffix"]
    cnt = ps_stats.get("counts", {}).get("-1", 0)
    pct = ps_stats.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "Prefix_Suffix",
        "feature_value": -1,
        "count": cnt,
        "denominator": denominator,
        "percentage": pct,
        "collection": model_type,
    }

    if cnt >= config.rule_10_min_count and pct >= config.rule_10_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Ubiquitous domain structure manipulation in phishing vectors.",
            trigger_reason=(
                f"Suspicious domain structure observed in {cnt} of {denominator} cases ({pct:.2f}%), "
                f"supporting deployment of reputation verification layers."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Domain signal below threshold.",
        trigger_reason=f"Observed count ({cnt}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 11: Outbound Web Access Controls
# ==============================================================================
def evaluate_rule_11_outbound_web_access(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_11_OUTBOUND_WEB_ACCESS"
    title = "Outbound web access controls"
    category = "Network security"
    rec_text = (
        "Consider reviewing outbound web access policies, allowing only business-required services and ports, "
        "and logging policy violations for investigation."
    )
    limitations = [
        "Port feature reflects non-preferred port usage in historical data.",
        "Does not infer an actual destination port or a confirmed network-policy violation from the encoded feature alone.",
    ]
    thresholds = {
        "minimum_count": config.rule_11_min_count,
        "minimum_percentage": config.rule_11_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "port" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Port feature statistics unavailable.",
            trigger_reason="Port feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    port_stats = feature_stats["port"]
    # port == -1 indicates non-preferred or restricted open ports
    cnt = port_stats.get("counts", {}).get("-1", 0)
    pct = port_stats.get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "port",
        "feature_value": -1,
        "count": cnt,
        "denominator": denominator,
        "percentage": pct,
        "collection": model_type,
    }

    if cnt >= config.rule_11_min_count and pct >= config.rule_11_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="medium",
            priority_reason="Non-standard or restricted port usage detected in significant phishing cohort.",
            trigger_reason=(
                f"Non-preferred port indicator ('port == -1') observed in {cnt} of {denominator} "
                f"cases ({pct:.2f}%), exceeding thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Port indicator below threshold.",
        trigger_reason=f"Observed count ({cnt}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 12: Security Awareness Training
# ==============================================================================
def evaluate_rule_12_security_awareness(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_12_SECURITY_AWARENESS"
    title = "Security awareness training"
    category = "People & process"
    rec_text = (
        "Consider providing employees with practical training on recognizing deceptive links, "
        "checking destination domains, and reporting suspicious messages."
    )
    limitations = [
        "Dataset evidence demonstrates high diversity of deceptive link patterns.",
        "Does not claim the dataset proves that employees have failed to recognize phishing.",
    ]
    thresholds = {
        "minimum_dataset_size": config.rule_12_min_dataset_size,
    }

    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)
    distinct_patterns = total_cases.get("distinct_vector_patterns", 0)

    if denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Record count unavailable.",
            trigger_reason="Record count unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    evidence = {
        "total_phishing_records": denominator,
        "distinct_vector_patterns": distinct_patterns,
        "collection": model_type,
    }

    if denominator >= config.rule_12_min_dataset_size:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Extensive volume of historical phishing examples demonstrates need for continuous human sensor awareness.",
            trigger_reason=(
                f"Dataset comprises {denominator} validated phishing vectors with {distinct_patterns} "
                f"distinct archetypes, justifying continuous user education on deceptive links."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Dataset size below threshold.",
        trigger_reason=f"Dataset size ({denominator}) below threshold ({config.rule_12_min_dataset_size}).",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 13: Lookalike-Domain Monitoring
# ==============================================================================
def evaluate_rule_13_lookalike_monitoring(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_13_LOOKALIKE_MONITORING"
    title = "Lookalike-domain monitoring"
    category = "Domain security"
    rec_text = (
        "Consider monitoring for newly registered domains resembling your organization's brand "
        "and creating a process for triaging likely impersonation attempts."
    )
    limitations = [
        "Does not claim that the project has discovered newly registered domains or performed external domain monitoring.",
        "Reflects measured prevalence of domain syntax patterns associated with impersonation.",
    ]
    thresholds = {
        "minimum_count": config.rule_13_min_count,
        "minimum_percentage": config.rule_13_min_percentage,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or "Prefix_Suffix" not in feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Prefix_Suffix statistics unavailable.",
            trigger_reason="Prefix_Suffix statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    cnt = feature_stats["Prefix_Suffix"].get("counts", {}).get("-1", 0)
    pct = feature_stats["Prefix_Suffix"].get("percentages", {}).get("-1", 0.0)

    evidence = {
        "feature": "Prefix_Suffix",
        "feature_value": -1,
        "count": cnt,
        "denominator": denominator,
        "percentage": pct,
        "collection": model_type,
    }

    if cnt >= config.rule_13_min_count and pct >= config.rule_13_min_percentage:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Near-universal adoption of domain manipulation tactics in phishing population.",
            trigger_reason=(
                f"Domain manipulation signal ('Prefix_Suffix == -1') observed in {cnt} of {denominator} "
                f"cases ({pct:.2f}%), supporting brand impersonation monitoring."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Domain signal below threshold.",
        trigger_reason=f"Observed count ({cnt}) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 14: Safe URL Detonation
# ==============================================================================
def evaluate_rule_14_safe_detonation(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_14_SAFE_URL_DETONATION"
    title = "Safe URL detonation"
    category = "Incident response"
    rec_text = (
        "Consider opening suspicious links only in an isolated analysis environment with controlled network access, "
        "rather than on employee workstations."
    )
    limitations = [
        "The engine must not fetch, open, or detonate any URLs.",
        "Reflects high concentrations of deceptive technical signals that warrant contained analysis.",
    ]
    thresholds = {
        "minimum_cluster_share_percentage": config.rule_14_min_cluster_share_pct,
    }

    clustering = analytics_bundle.get("clustering", {})
    cluster_sizes = clustering.get("cluster_sizes", [])
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not cluster_sizes or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Clustering evidence unavailable.",
            trigger_reason="Clustering evidence unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    dominant_cluster = max(cluster_sizes, key=lambda c: c.get("member_count", 0))
    share_pct = dominant_cluster.get("percentage", 0.0)

    evidence = {
        "dominant_cluster_id": dominant_cluster.get("cluster_id"),
        "cluster_member_count": dominant_cluster.get("member_count"),
        "cluster_share_percentage": share_pct,
        "denominator": denominator,
        "collection": model_type,
    }

    if share_pct >= config.rule_14_min_cluster_share_pct:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Dominant threat clusters represent high-density risk patterns requiring contained handling.",
            trigger_reason=(
                f"Dominant threat archetype cluster {dominant_cluster.get('cluster_id')} encompasses "
                f"{dominant_cluster.get('member_count')} samples ({share_pct:.2f}% of population)."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Dominant cluster share below threshold.",
        trigger_reason=f"Dominant cluster share ({share_pct:.2f}%) below threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 15: Web Gateway Policy Review
# ==============================================================================
def evaluate_rule_15_web_gateway_review(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_15_WEB_GATEWAY_REVIEW"
    title = "Web gateway policy review"
    category = "Web security"
    rec_text = (
        "Consider reviewing secure web gateway policies to ensure suspicious destinations are inspected, "
        "blocked when justified, and logged for later investigation."
    )
    limitations = [
        "Does not claim that an existing gateway is missing controls; the project does not inspect organizational infrastructure.",
    ]
    thresholds = {
        "minimum_qualifying_signals": config.rule_15_min_qualifying_signals,
        "signal_minimum_percentage": config.rule_15_signal_min_pct,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Feature statistics unavailable.",
            trigger_reason="Feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    # Count high-prevalence risk signals (-1)
    qualifying_feats = []
    for fname, fstat in feature_stats.items():
        pct_neg1 = fstat.get("percentages", {}).get("-1", 0.0)
        if pct_neg1 >= config.rule_15_signal_min_pct:
            qualifying_feats.append({"feature": fname, "percentage": pct_neg1})

    evidence = {
        "qualifying_signals_count": len(qualifying_feats),
        "qualifying_signals": qualifying_feats,
        "denominator": denominator,
        "collection": model_type,
    }

    if len(qualifying_feats) >= config.rule_15_min_qualifying_signals:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Multiple independent URL risk signals demonstrate pervasive circumvention tactics.",
            trigger_reason=(
                f"Identified {len(qualifying_feats)} independently measured URL risk signals exceeding "
                f"{config.rule_15_signal_min_pct}% prevalence in the phishing population."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Fewer than required signals met threshold.",
        trigger_reason=f"Only {len(qualifying_feats)} signals met threshold.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 16: Cluster-Driven Detection Rules
# ==============================================================================
def evaluate_rule_16_cluster_detection_rules(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_16_CLUSTER_DETECTION_RULES"
    title = "Cluster-driven detection rules"
    category = "Detection engineering"
    rec_text = (
        "Consider reviewing the recurring feature combination and, if validated against real examples, "
        "creating a targeted detection rule in your existing email or web security controls."
    )
    limitations = [
        "Do not recommend a hard blocking rule solely because a cluster exists.",
        "Clusters are descriptive groups, not proof of a specific coordinated campaign or attacker.",
    ]
    thresholds = {
        "minimum_cluster_size": config.rule_16_min_cluster_size,
        "minimum_cluster_share_percentage": config.rule_16_min_cluster_share_pct,
    }

    clustering = analytics_bundle.get("clustering", {})
    cluster_profiles = analytics_bundle.get("cluster_profiles", {})
    cluster_sizes = clustering.get("cluster_sizes", [])
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not cluster_sizes or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Clustering data unavailable.",
            trigger_reason="Clustering data unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    qualifying_clusters = [
        cs for cs in cluster_sizes
        if cs.get("member_count", 0) >= config.rule_16_min_cluster_size
        and cs.get("percentage", 0.0) >= config.rule_16_min_cluster_share_pct
    ]

    evidence = {
        "qualifying_clusters_count": len(qualifying_clusters),
        "qualifying_clusters_summary": qualifying_clusters,
        "clustering_algorithm": clustering.get("algorithm"),
        "total_clusters": clustering.get("n_clusters"),
        "denominator": denominator,
        "collection": model_type,
    }

    if qualifying_clusters:
        top_cluster = qualifying_clusters[0]
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Clustering identified robust, recurring archetypes representing large proportions of phishing cases.",
            trigger_reason=(
                f"Cluster {top_cluster.get('cluster_id')} comprises {top_cluster.get('member_count')} "
                f"records ({top_cluster.get('percentage'):.2f}% of population), exceeding support thresholds."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="No clusters satisfied both size and percentage thresholds.",
        trigger_reason="No clusters satisfied both size and percentage thresholds.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 17: Rare-Pattern Investigation
# ==============================================================================
def evaluate_rule_17_rare_pattern_investigation(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_17_RARE_PATTERN_INVESTIGATION"
    title = "Rare-pattern investigation"
    category = "Threat hunting"
    rec_text = (
        "Consider routing rare URL-feature patterns for additional inspection and analyst review "
        "instead of automatically blocking them solely because they are uncommon."
    )
    limitations = [
        "Do not automatically block or classify a record as malicious because its pattern is rare.",
        "Describes infrequent combinations in historical phishing vectors.",
    ]
    thresholds = {
        "minimum_rare_patterns": config.rule_17_min_rare_patterns,
        "maximum_rarity_count": config.rule_17_max_rarity_count,
    }

    unusual_patterns = analytics_bundle.get("unusual_patterns", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not unusual_patterns or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Unusual patterns evidence unavailable.",
            trigger_reason="Unusual patterns evidence unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    rare_pattern_count = unusual_patterns.get("rare_pattern_count", 0)
    rare_sample_count = unusual_patterns.get("rare_sample_count", 0)
    rare_pct = unusual_patterns.get("rare_sample_percentage", 0.0)

    evidence = {
        "rare_pattern_count": rare_pattern_count,
        "rare_sample_count": rare_sample_count,
        "rare_sample_percentage": rare_pct,
        "rarity_count_threshold": unusual_patterns.get("rarity_count_threshold"),
        "denominator": denominator,
        "collection": model_type,
    }

    if rare_pattern_count >= config.rule_17_min_rare_patterns:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="medium",
            priority_reason="Significant catalog of rare/unusual feature combinations identified for threat hunting triage.",
            trigger_reason=(
                f"Identified {rare_pattern_count} distinct rare feature patterns encompassing {rare_sample_count} "
                f"records ({rare_pct:.2f}% of dataset), exceeding minimum ({config.rule_17_min_rare_patterns})."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Fewer rare patterns found than threshold.",
        trigger_reason=f"Rare pattern count ({rare_pattern_count}) below threshold ({config.rule_17_min_rare_patterns}).",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 18: Layered Phishing Defenses
# ==============================================================================
def evaluate_rule_18_layered_defenses(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_18_LAYERED_DEFENSES"
    title = "Layered phishing defenses"
    category = "Security strategy"
    rec_text = (
        "Consider using layered controls across email filtering, web reputation, domain validation, "
        "endpoint protection, and employee reporting rather than relying on a single detection signal."
    )
    limitations = [
        "Do not count several correlated features as independent evidence without acknowledging their relationship.",
        "Reflects diverse technical layers represented in observed threat patterns.",
    ]
    thresholds = {
        "minimum_distinct_categories": config.rule_18_min_distinct_categories,
        "category_minimum_percentage": config.rule_18_category_min_pct,
    }

    feature_stats = analytics_bundle.get("feature_statistics", {})
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not feature_stats or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Feature statistics unavailable.",
            trigger_reason="Feature statistics unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    # Classify features into distinct technical defensive layers
    # Layer 1: Domain / URL Structure (Prefix_Suffix, URL_Length, having_Sub_Domain)
    # Layer 2: Network / Transport (having_IP_Address, port, SSLfinal_State)
    # Layer 3: Content / Application (URL_of_Anchor, Request_URL, SFH, Submitting_to_email)
    layer_counts = {"domain_structure": 0, "network_transport": 0, "content_application": 0}

    for f_domain in ["Prefix_Suffix", "URL_Length", "having_Sub_Domain"]:
        if f_domain in feature_stats and feature_stats[f_domain].get("percentages", {}).get("-1", 0.0) >= config.rule_18_category_min_pct:
            layer_counts["domain_structure"] += 1

    for f_net in ["having_IP_Address", "port", "SSLfinal_State"]:
        if f_net in feature_stats and feature_stats[f_net].get("percentages", {}).get("-1", 0.0) >= config.rule_18_category_min_pct:
            layer_counts["network_transport"] += 1

    for f_app in ["URL_of_Anchor", "Request_URL", "SFH", "Submitting_to_email"]:
        if f_app in feature_stats and feature_stats[f_app].get("percentages", {}).get("-1", 0.0) >= config.rule_18_category_min_pct:
            layer_counts["content_application"] += 1

    active_layers = [k for k, v in layer_counts.items() if v > 0]

    evidence = {
        "qualifying_layers_count": len(active_layers),
        "qualifying_layers": active_layers,
        "layer_counts": layer_counts,
        "denominator": denominator,
        "collection": model_type,
    }

    if len(active_layers) >= config.rule_18_min_distinct_categories:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Observed threat patterns simultaneously span multiple distinct security layers.",
            trigger_reason=(
                f"Observed robust threat signals across {len(active_layers)} distinct layers "
                f"({', '.join(active_layers)}), demonstrating need for defense-in-depth."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Fewer than required defensive layers qualified.",
        trigger_reason="Fewer than required defensive layers qualified.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 19: Security Control Effectiveness Review (Time-Series)
# ==============================================================================
def evaluate_rule_19_control_effectiveness(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_19_CONTROL_EFFECTIVENESS"
    title = "Security control effectiveness review"
    category = "Security operations"
    rec_text = (
        "Consider reviewing whether current email and web controls are detecting and blocking "
        "the observed patterns, and track confirmed incidents and false positives to identify gaps."
    )
    limitations = [
        "If trustworthy detection timestamps are unavailable, this rule must not claim that threats are growing over time.",
        "The engine does not have access to live organizational incident outcomes.",
    ]
    thresholds = {
        "minimum_time_windows": config.rule_19_min_time_windows,
        "minimum_trend_records": config.rule_19_min_trend_records,
    }

    summary = analytics_bundle.get("summary", {})
    ts_disc = summary.get("timestamp_handling_disclosure", {})
    trends_avail = ts_disc.get("historical_time_trends_available", False)

    evidence = {
        "historical_time_trends_available": trends_avail,
        "disclosure_notes": ts_disc.get("observed_at_semantics", "No event timestamps available in source data."),
        "collection": model_type,
    }

    # Strict compliance: if trustworthy detection event timestamps are unavailable,
    # rule must not claim threats are growing. Return insufficient_evidence / not_triggered.
    if not trends_avail:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="low",
            priority_reason="Trustworthy event-level historical timestamps unavailable in dataset.",
            trigger_reason=(
                "Historical detection event timestamps are not present in source dataset (observed_at "
                "reflects database ingestion). Time-series trend evaluation is not supported without fabricated dates."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    # Fallback if trends were available
    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Time windows did not demonstrate required growth trend.",
        trigger_reason="Time windows did not demonstrate required growth trend.",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# ==============================================================================
# RULE 20: Prioritize the Strongest Evidence
# ==============================================================================
def evaluate_rule_20_prioritize_strongest_evidence(
    analytics_bundle: Dict[str, Any],
    config: RecommendationConfig,
    model_type: str,
) -> Dict[str, Any]:
    rule_id = "RULE_20_PRIORITIZE_STRONGEST_EVIDENCE"
    title = "Prioritize the strongest evidence"
    category = "Risk prioritization"
    rec_text = (
        "Consider prioritizing a review of controls related to the most consistently observed phishing patterns, "
        "using the measured counts, prevalence, and validation status to guide effort."
    )
    limitations = [
        "Ranking is based on observed prevalence in historical phishing vectors.",
        "Do not equate frequency with severity or assume the most frequent signal represents the highest business risk.",
    ]
    thresholds = {
        "minimum_top_signal_percentage": config.rule_20_min_top_signal_pct,
    }

    top_signals = analytics_bundle.get("top_signals", [])
    total_cases = analytics_bundle.get("total_cases", {})
    denominator = total_cases.get("valid_phishing_records", 0)

    if not top_signals or denominator == 0:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="insufficient_evidence", priority="medium",
            priority_reason="Top signals evidence unavailable.",
            trigger_reason="Top signals evidence unavailable.",
            evidence={}, thresholds=thresholds, limitations=limitations
        )

    top_1 = top_signals[0]
    top_pct = top_1.get("percentage", 0.0)

    evidence = {
        "top_signal": top_1.get("signal_name"),
        "top_signal_count": top_1.get("count"),
        "top_signal_percentage": top_pct,
        "top_3_signals": [s.get("signal_name") for s in top_signals[:3]],
        "denominator": denominator,
        "collection": model_type,
    }

    if top_pct >= config.rule_20_min_top_signal_pct:
        return _build_rec_dict(
            rule_id, model_type, title, category, rec_text,
            status="triggered", priority="high",
            priority_reason="Dominant signal observed with extreme prevalence across phishing population.",
            trigger_reason=(
                f"Rank 1 signal '{top_1.get('signal_name')}' observed in {top_1.get('count')} "
                f"cases ({top_pct:.2f}% of population), providing strong empirical grounding for focus."
            ),
            evidence=evidence, thresholds=thresholds, limitations=limitations
        )

    return _build_rec_dict(
        rule_id, model_type, title, category, rec_text,
        status="not_triggered", priority="low",
        priority_reason="Top signal prevalence below threshold.",
        trigger_reason=f"Top signal prevalence ({top_pct:.2f}%) below threshold ({config.rule_20_min_top_signal_pct}%).",
        evidence=evidence, thresholds=thresholds, limitations=limitations
    )


# Rule Registry mapping rule_id -> evaluation function
ALL_RULES = [
    evaluate_rule_1_shortened_url,
    evaluate_rule_2_ip_address_links,
    evaluate_rule_3_lookalike_domain,
    evaluate_rule_4_subdomain_review,
    evaluate_rule_5_https_validation,
    evaluate_rule_6_url_normalization,
    evaluate_rule_7_external_link_inspection,
    evaluate_rule_8_attachment_link_defense,
    evaluate_rule_9_sender_authentication,
    evaluate_rule_10_domain_reputation,
    evaluate_rule_11_outbound_web_access,
    evaluate_rule_12_security_awareness,
    evaluate_rule_13_lookalike_monitoring,
    evaluate_rule_14_safe_detonation,
    evaluate_rule_15_web_gateway_review,
    evaluate_rule_16_cluster_detection_rules,
    evaluate_rule_17_rare_pattern_investigation,
    evaluate_rule_18_layered_defenses,
    evaluate_rule_19_control_effectiveness,
    evaluate_rule_20_prioritize_strongest_evidence,
]
