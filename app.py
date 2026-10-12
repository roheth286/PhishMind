"""
Streamlit Web Application for Phishing URL Detection and Threat Intelligence.

Architecture:
- Simple, clean 3-view navigation:
  1. URL Input View
  2. Prediction Result View
  3. Analysis Dashboard View
- Strictly reuses existing backend modules:
  - src.pipeline_router (route_url, RoutingResult)
  - src.threat_vector_db (get_collection_stats)
  - src.threat_recommendations (load_analytics_evidence, get_current_recommendation_state)
  - src.threat_integration_service (get_current_recommendation_state)
- Performs lightweight input validation prior to backend invocation.
- Reuses existing threat database, analytics, clustering, and recommendation outputs.
- Never reveals or stores raw URLs in threat intelligence outputs.
"""

import os
import sys
import pandas as pd
import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.pipeline_router import route_url
from src.threat_integration_service import get_current_recommendation_state
from src.threat_recommendations import load_analytics_evidence
from src.threat_vector_db import FEATURES_10, FEATURES_20, get_collection_stats
from src.ui_validator import validate_url_format

st.set_page_config(
    page_title="Phishing Detection & Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
)


# ------------------------------------------------------------------------------
# Session State Initialization
# ------------------------------------------------------------------------------
if "current_view" not in st.session_state:
    st.session_state["current_view"] = "url_input"
if "prediction_result" not in st.session_state:
    st.session_state["prediction_result"] = None
if "submitted_url" not in st.session_state:
    st.session_state["submitted_url"] = ""
if "validation_error" not in st.session_state:
    st.session_state["validation_error"] = None


# ------------------------------------------------------------------------------
# Navigation Helper
# ------------------------------------------------------------------------------
def navigate_to(view_name: str):
    st.session_state["current_view"] = view_name
    st.rerun()


# ==============================================================================
# VIEW 1: URL Input
# ==============================================================================
def render_url_input_view():
    st.title("🛡️ Phishing Detection System")
    st.markdown(
        """
        Welcome to the **Intelligent Phishing URL Detection & Threat Analysis Platform**.
        
        This system utilizes adaptive dual-pipeline machine learning models:
        - **Pipeline A (Full 20-Feature Model):** Active when responsive HTML content is verified.
        - **Pipeline B (Reduced 10-Feature Model):** Fast network and structural analysis when web resources are redirected, non-HTML, or unavailable.
        
        Enter any URL below to inspect and classify its threat profile.
        """
    )
    st.divider()

    col1, col2 = st.columns([3, 1])
    with col1:
        user_url = st.text_input(
            "Enter URL to analyze:",
            value=st.session_state["submitted_url"],
            placeholder="e.g., https://secure-bank-login.example.com/account",
            help="Enter a complete URL or domain name.",
        )

    predict_clicked = st.button("🔍 Predict URL", type="primary", use_container_width=False)

    if st.session_state.get("validation_error"):
        st.error(st.session_state["validation_error"])

    if predict_clicked:
        # Step 1: Lightweight format validation
        is_valid, validation_msg = validate_url_format(user_url)
        if not is_valid:
            st.session_state["validation_error"] = f"❌ {validation_msg}"
            st.rerun()

        st.session_state["validation_error"] = None
        st.session_state["submitted_url"] = user_url

        # Step 2: Call existing backend pipeline router
        with st.spinner("Analyzing destination resource and extracting feature vector..."):
            try:
                # route_url automatically performs HTTP check, selects pipeline (10 vs 20),
                # extracts features, predicts class, and executes threat intelligence storage if phishing
                res = route_url(
                    url=user_url,
                    update_threat_intel=True,
                )
                st.session_state["prediction_result"] = res
                st.session_state["current_view"] = "prediction_result"
                st.rerun()
            except Exception as e:
                st.error(f"⚠️ Prediction execution failed: {str(e)}")


# ==============================================================================
# VIEW 2: Prediction Result
# ==============================================================================
def render_prediction_result_view():
    st.title("📊 Prediction Result")
    res = st.session_state.get("prediction_result")

    if not res:
        st.warning("No active prediction found. Please submit a URL for analysis.")
        if st.button("⬅️ Back to URL Input"):
            navigate_to("url_input")
        return

    # Top Navigation Row
    top_col1, top_col2, _ = st.columns([1, 1, 3])
    with top_col1:
        if st.button("⬅️ Analyze Another URL"):
            navigate_to("url_input")
    with top_col2:
        if st.button("📈 Analysis Dashboard ➡️", type="primary"):
            navigate_to("analysis_dashboard")

    st.divider()

    # Result Banner
    is_phishing = (res.predicted_label == -1)
    if is_phishing:
        st.error(
            f"### 🚨 Classification: **PHISHING**\n"
            f"The analyzed URL matches high-risk phishing threat signatures."
        )
    else:
        st.success(
            f"### ✅ Classification: **LEGITIMATE**\n"
            f"The analyzed destination displays authentic structural and resource characteristics."
        )

    # Core Metrics Cards
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric(
            label="Predicted Label",
            value=f"{res.predicted_label} ({res.label_description})",
        )
    with m_col2:
        st.metric(
            label="Phishing Probability",
            value=f"{res.phishing_probability * 100:.2f}%",
        )
    with m_col3:
        st.metric(
            label="Pipeline Selected",
            value=res.pipeline,
        )
    with m_col4:
        st.metric(
            label="Feature Vector Count",
            value=f"{res.feature_count} features",
        )

    # Detailed Decision Breakdown
    st.subheader("Routing & Inspection Context")
    st.markdown(
        f"""
        - **Routing Reason:** `{res.routing_reason}`
        - **HTTP Status Code:** `{res.status_code if res.status_code is not None else 'N/A'}`
        - **Content-Type Header:** `{res.content_type if res.content_type is not None else 'N/A'}`
        - **Destination URL:** `{res.final_url if res.final_url is not None else 'N/A'}`
        """
    )

    # Feature Vector Display
    with st.expander("🔍 View Extracted Feature Vector", expanded=False):
        st.write("Feature values (`-1`: Phishing / Suspicious, `0`: Moderate / Neutral, `1`: Legitimate):")
        
        # Determine expected feature schema based on pipeline / feature count
        vec = list(res.feature_vector)
        vec_len = len(vec)
        is_10_feature = (res.feature_count == 10 or getattr(res, "pipeline", "") == "10-feature")
        
        if is_10_feature:
            expected_names = list(FEATURES_10)
        else:
            expected_names = list(FEATURES_20)

        # Check if vector genuinely includes the target label 'Result' at the end
        if vec_len == len(expected_names) + 1:
            col_names = expected_names + ["Result"]
        elif vec_len == len(expected_names):
            col_names = expected_names
        else:
            col_names = None

        if col_names is not None:
            # Build DataFrame with feature names as column headers
            # Index includes "Feature Index" and "Value" rows for clarity
            feat_df = pd.DataFrame(
                [
                    list(range(1, vec_len + 1)),
                    vec,
                ],
                index=["Feature Index", "Value"],
                columns=col_names,
            )
            st.dataframe(feat_df, use_container_width=True)
        else:
            st.warning(
                f"⚠️ Extracted vector length ({vec_len}) does not match expected schema "
                f"({len(expected_names)} features). Displaying raw vector to prevent mislabeling."
            )
            raw_df = pd.DataFrame({
                "Feature Index": range(1, vec_len + 1),
                "Value": vec,
            })
            st.dataframe(raw_df.T, use_container_width=True)

    # Threat Intelligence Action Notice
    if is_phishing:
        ti = res.threat_intel
        if ti and ti.get("stored"):
            st.info(
                f"🛡️ **Threat Intelligence Update:** This phishing pattern was securely ingested "
                f"into the ChromaDB `{ti.get('model_type')}` collection. "
                f"Cluster profiles, rare patterns, and defensive recommendations have been refreshed."
            )
        elif ti and ti.get("status") == "duplicate_event":
            st.info("ℹ️ **Threat Intelligence Notice:** This event was previously cataloged.")


# ==============================================================================
# VIEW 3: Analysis Dashboard
# ==============================================================================
def render_analysis_dashboard_view():
    st.title("📈 Threat Activity & Intelligence Dashboard")

    top_col1, top_col2, _ = st.columns([1, 1, 3])
    with top_col1:
        if st.button("⬅️ Back to Prediction"):
            navigate_to("prediction_result")
    with top_col2:
        if st.button("🔍 Analyze New URL"):
            navigate_to("url_input")

    st.divider()

    # Model Collection Selector
    col_sel_col, _ = st.columns([2, 3])
    with col_sel_col:
        selected_model_type = st.radio(
            "Select Intelligence Collection:",
            options=["10_features", "20_features"],
            format_func=lambda x: "10-Feature Pipeline (Fast / Structural)" if x == "10_features" else "20-Feature Pipeline (Comprehensive HTML)",
            horizontal=True,
        )

    # Load baseline analytics and recommendation states using existing backend
    evidence_bundle = load_analytics_evidence(selected_model_type)
    rec_state = get_current_recommendation_state(selected_model_type)
    db_stats = get_collection_stats(selected_model_type)

    total_cases = evidence_bundle.get("total_cases", {})
    summary = evidence_bundle.get("summary", {})
    feature_stats = evidence_bundle.get("feature_statistics", {})
    clustering = evidence_bundle.get("clustering", {})
    cluster_profiles = evidence_bundle.get("cluster_profiles", {})
    unusual_patterns = evidence_bundle.get("unusual_patterns", {})
    dq_report = evidence_bundle.get("data_quality", {})

    # --------------------------------------------------------------------------
    # SECTION A: Overview Metrics
    # --------------------------------------------------------------------------
    st.subheader("1. Overview Metrics")
    m1, m2, m3, m4, m5 = st.columns(5)

    with m1:
        st.metric("Total Stored Cases", f"{db_stats.get('count', total_cases.get('valid_phishing_records', 0)):,}")
    with m2:
        st.metric("Distinct Vectors", f"{total_cases.get('distinct_vector_patterns', 0):,}")
    with m3:
        st.metric("Total Clusters", f"{clustering.get('n_clusters', 0)}")
    with m4:
        st.metric("Active Recommendations", f"{rec_state.get('evaluation_summary', {}).get('active_recommendations_count', 0)}")
    with m5:
        trans = rec_state.get("recommendation_transitions", {})
        st.metric("Newly Triggered", f"{trans.get('newly_triggered_count', 0)}")

    st.markdown("---")

    # --------------------------------------------------------------------------
    # SECTION B: Feature Analytics
    # --------------------------------------------------------------------------
    st.subheader("2. Feature Analytics & Signal Prevalence")

    if feature_stats:
        feat_rows = []
        for feat_name, s in feature_stats.items():
            cnts = s.get("counts", {})
            pcts = s.get("percentages", {})
            feat_rows.append({
                "Feature Name": feat_name,
                "Phishing (-1) %": pcts.get("-1", 0.0),
                "Neutral (0) %": pcts.get("0", 0.0),
                "Legitimate (1) %": pcts.get("1", 0.0),
                "Phishing (-1) Count": cnts.get("-1", 0),
                "Neutral (0) Count": cnts.get("0", 0),
                "Legitimate (1) Count": cnts.get("1", 0),
            })

        df_feats = pd.DataFrame(feat_rows)

        tab_chart, tab_table, tab_signals = st.tabs(["📊 Value Distribution Chart", "📋 Complete Statistics Table", "⭐ Top Threat Signals"])

        with tab_chart:
            st.caption("Distribution of categorical feature values across historical phishing cases:")
            chart_df = df_feats.set_index("Feature Name")[["Phishing (-1) %", "Neutral (0) %", "Legitimate (1) %"]]
            st.bar_chart(chart_df, height=350)

        with tab_table:
            st.dataframe(df_feats, use_container_width=True)

        with tab_signals:
            top_sigs = evidence_bundle.get("top_signals", [])
            if top_sigs:
                sig_df = pd.DataFrame(top_sigs)[["signal_name", "count", "percentage"]]
                sig_df.columns = ["Threat Signal Condition", "Observed Count", "Support Percentage (%)"]
                st.dataframe(sig_df, use_container_width=True)
            else:
                st.info("Top signals data unavailable.")
    else:
        st.info("Feature statistics data unavailable for this collection.")

    st.markdown("---")

    # --------------------------------------------------------------------------
    # SECTION C: Cluster Analysis
    # --------------------------------------------------------------------------
    st.subheader("3. Cluster Analysis & Archetypes")

    c_col1, c_col2 = st.columns([1, 1])
    with c_col1:
        st.markdown(f"**Clustering Algorithm:** `{clustering.get('algorithm', 'KMeans')} (k={clustering.get('n_clusters', 4)})`")
        st.markdown(f"**Silhouette Score:** `{clustering.get('silhouette_score', 'N/A')}`")
        st.markdown(f"**Distance Metric:** `{clustering.get('distance_metric', 'euclidean')}`")

        cluster_sizes = clustering.get("cluster_sizes", [])
        if cluster_sizes:
            c_size_df = pd.DataFrame(cluster_sizes)[["cluster_id", "member_count", "percentage", "distinct_vector_patterns_count"]]
            c_size_df.columns = ["Cluster ID", "Members", "Population Share (%)", "Distinct Patterns"]
            st.dataframe(c_size_df, use_container_width=True)

    with c_col2:
        if cluster_sizes:
            c_chart_df = pd.DataFrame(cluster_sizes).set_index("cluster_id")["member_count"]
            st.caption("Cluster member distribution:")
            st.bar_chart(c_chart_df, height=220)

    # Cluster Profiles Expanders
    if cluster_profiles:
        with st.expander("🔍 View Detailed Cluster Feature Profiles", expanded=False):
            for c_key, c_data in cluster_profiles.items():
                st.markdown(f"#### Cluster {c_data.get('cluster_id')} ({c_data.get('member_count')} cases, {c_data.get('percentage_of_total')}%)")
                prof_rows = []
                for f_name, f_info in c_data.get("features", {}).items():
                    prof_rows.append({
                        "Feature": f_name,
                        "Uniform Invariant?": "✅ Yes" if f_info.get("is_uniform") else "No",
                        "Dominant Value(s)": str(f_info.get("dominant_values")),
                        "Centroid Value": f_info.get("centroid_value"),
                    })
                st.dataframe(pd.DataFrame(prof_rows), use_container_width=True)

    # Unusual Patterns Summary
    if unusual_patterns:
        with st.expander("⚡ Rare Pattern & Threat Hunting Analysis", expanded=False):
            st.markdown(
                f"- **Rare Pattern Count:** `{unusual_patterns.get('rare_pattern_count', 0)}`\n"
                f"- **Total Affected Records:** `{unusual_patterns.get('rare_sample_count', 0)}` ({unusual_patterns.get('rare_sample_percentage', 0.0)}% of population)\n"
                f"- **Rarity Threshold:** Occurrence &le; {unusual_patterns.get('rarity_count_threshold', 2)}"
            )
            rare_pats = unusual_patterns.get("rare_patterns", [])[:10]
            if rare_pats:
                st.write("Top 10 sample rare vector signatures:")
                st.json(rare_pats)

    st.markdown("---")

    # --------------------------------------------------------------------------
    # SECTION D: Recommendations and Evidence Summaries
    # --------------------------------------------------------------------------
    st.subheader("4. Defensive Recommendations & Evidence Summaries")

    active_recs = rec_state.get("active_recommendations", [])
    trans = rec_state.get("recommendation_transitions", {})
    newly_trig_ids = {r["rule_id"] for r in trans.get("newly_triggered", [])}

    if active_recs:
        for idx, rec in enumerate(active_recs):
            is_new = rec["rule_id"] in newly_trig_ids
            badge = "🔥 [NEWLY TRIGGERED]" if is_new else f"[{rec.get('priority', 'medium').upper()} PRIORITY]"
            
            with st.container():
                st.markdown(f"### {idx + 1}. {badge} {rec.get('title', 'Recommendation')}")
                st.markdown(f"**Category:** `{rec.get('category')}` | **Rule ID:** `{rec.get('rule_id')}`")
                st.info(f"💡 **Recommendation:** {rec.get('recommendation')}")
                st.markdown(f"**Trigger Rationale:** {rec.get('trigger_reason')}")

                with st.expander("📋 View Supporting Evidence & Configuration", expanded=False):
                    e_col1, e_col2 = st.columns(2)
                    with e_col1:
                        st.write("**Measured Evidence:**")
                        st.json(rec.get("evidence", {}))
                    with e_col2:
                        st.write("**Evaluation Thresholds:**")
                        st.json(rec.get("thresholds", {}))

                    st.write("**Observational Limitations:**")
                    for lim in rec.get("limitations", []):
                        st.markdown(f"- *{lim}*")
                st.divider()
    else:
        st.info("No active recommendations currently qualify for display.")

    # --------------------------------------------------------------------------
    # SECTION E: Data Quality
    # --------------------------------------------------------------------------
    st.subheader("5. Data Quality & Audit Integrity")
    if dq_report:
        q1, q2, q3 = st.columns(3)
        with q1:
            st.metric("Data Quality Score", f"{dq_report.get('data_quality_percentage', 100.0):.2f}%")
        with q2:
            st.metric("Valid Records", f"{dq_report.get('valid_records_count', 0):,}")
        with q3:
            st.metric("Invalid Records", f"{dq_report.get('invalid_records_count', 0)}")

        st.caption(f"Audit Status: `{dq_report.get('status')}` | Notes: {dq_report.get('notes')}")
    else:
        st.info("Data quality report unavailable.")


# ==============================================================================
# MAIN ROUTER
# ==============================================================================
def main():
    current_view = st.session_state.get("current_view", "url_input")

    if current_view == "url_input":
        render_url_input_view()
    elif current_view == "prediction_result":
        render_prediction_result_view()
    elif current_view == "analysis_dashboard":
        render_analysis_dashboard_view()
    else:
        render_url_input_view()


if __name__ == "__main__":
    main()
