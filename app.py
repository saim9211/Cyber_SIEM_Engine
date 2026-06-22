import streamlit as st
import pandas as pd
import joblib
import numpy as np
import time

# 1. Page Configuration & Theme Accents
st.set_page_config(
    page_title="Cyber-Forensics AI SOC", 
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS Injection for a clean, modern dashboard look
st.markdown("""
    <style>
    .main { background-color: #1183D6; color: #ffffff; }
    .block-container { padding-top: 1.5rem; padding-bottom: 1.5rem; }
    .stButton>button { border-radius: 1rem; background-color: #0c6fc6; color: #ffffff; border: none; padding: 0.95rem 1.3rem; box-shadow: 0 12px 28px rgba(17, 131, 214, 0.18); }
    .stButton>button:hover { background-color: #0a63b5; }
    .stMetric { background-color: #1183D6; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.2); padding: 1.2rem 1rem; box-shadow: 0 10px 24px rgba(0, 0, 0, 0.08); color: #ffffff; }
    section[data-testid="stSidebar"] { background-color: #1183D6; border-right: 1px solid rgba(255,255,255,0.2); }
    div[data-testid="stExpander"] { background-color: #1183D6; border-radius: 1rem; border: 1px solid rgba(255,255,255,0.2); color: #ffffff; }
    button[role="tab"] { color: #ffffff !important; background-color: #0f75c4 !important; border: 1px solid rgba(255,255,255,0.2) !important; border-bottom: none !important; padding: 0.85rem 1rem; margin-right: 0.2rem; }
    button[role="tab"][aria-selected="true"] { color: #ffffff !important; background-color: #0a64b2 !important; border-color: #0a64b2 !important; }
    div[role="tabpanel"] { background-color: #1183D6 !important; color: #ffffff !important; border: 1px solid rgba(255,255,255,0.2) !important; border-radius: 0 0 1rem 1rem !important; padding: 1.5rem !important; }
    .css-1d391kg { background-color: #1183D6 !important; }
    .stTextInput>div>div>input { border-radius: 0.95rem !important; border: 1px solid rgba(255,127,127,0.3) !important; background-color: rgba(255,255,255,0.1) !important; color: #ffffff !important; }
    .stTextInput label, .stTextInput span, .stTextInput div>label { color: #ffffff !important; }
    </style>
""", unsafe_allow_html=True)

# 2. Cached Model Loader
@st.cache_resource
def load_security_brain():
    return joblib.load("security_pipeline_model.pkl")

try:
    production_pipeline = load_security_brain()
except FileNotFoundError:
    st.error("🚨 Error: 'security_pipeline_model.pkl' not found. Please run 'train_model.py' first to build the brain file.")
    st.stop()

# 3. Sidebar Configuration Pane
st.sidebar.image("https://img.icons8.com/fluent/96/000000/shield.png", width=70)
st.sidebar.title("Data Ingestion Control")
st.sidebar.markdown("Simulate live network metrics entering the server firewall.")

st.sidebar.markdown("---")

user_protocol = st.sidebar.selectbox(
    "🌐 Network Protocol Type",
    options=['HTTP', 'TCP', 'UDP'],
    help="Select the structural protocol layer of the incoming data request packet."
)

user_packet_size = st.sidebar.slider(
    "📦 Packet Payload Size (Bytes)",
    min_value=64,
    max_value=30000,
    value=1200,
    step=100,
    help="Oversized packets often hint at a payload exploitation or a massive DDoS surge."
)

user_logins = st.sidebar.slider(
    "🔑 Sequential Login Attempts",
    min_value=0,
    max_value=25,
    value=1,
    help="Rapid, continuous failed authentication attempts indicate brute-force patterns."
)

st.sidebar.markdown("---")
analyze_btn = st.sidebar.button("⚡ Run Forensic Analysis", use_container_width=True, type="primary")

# 4. Main Executive Header Layout
title_col, logo_col = st.columns([0.75, 0.25])
with title_col:
    st.title("🛡️ Enterprise Cyber-Forensics AI Detection Control")
    st.caption("A polished SOC interface with calm blue accents, clean data panels, and instantly readable telemetry.")
with logo_col:
    st.image("https://img.icons8.com/fluency/96/000000/cyber-security.png", width=96)

st.markdown("---")

# 5. Organizing the Layout with Professional Tabs
tab_engine, tab_logs = st.tabs([
    "🔍 Real-Time Detection Engine", 
    "📊 Threat Telemetry Analytics"
])

# ==============================================================================
# TAB 1: THE ACTIVE DETECTION ENGINE
# ==============================================================================
with tab_engine:
    if analyze_btn:
        # Create a clean mock ingestion loading feedback sequence
        with st.spinner("Parsing raw textual log byte-streams and querying firewall cache..."):
            time.sleep(0.4)
            
        # Formulate data structure row matching pipeline feature mapping exactly
        live_input_row = pd.DataFrame({
            'protocol_type': [user_protocol],
            'packet_size_bytes': [user_packet_size],
            'login_attempts': [user_logins]
        })
        
        # Compute Inference
        prediction = production_pipeline.predict(live_input_row)[0]
        probabilities = production_pipeline.predict_proba(live_input_row)[0]
        
        safe_prob = probabilities[0] * 100
        attack_prob = probabilities[1] * 100
        
        # Metric Grid Layout
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric(label="System Security Status", value="ANOMALY DETECTED" if prediction == 1 else "SECURE RUNTIME")
        with m2:
            st.metric(label="Malicious Threat Likelihood", value=f"{attack_prob:.1f}%", delta=f"{attack_prob-20:.1f}%" if attack_prob > 50 else None, delta_color="inverse")
        with m3:
            st.metric(label="Data Ingestion Rate", value="1.24 Gbps", delta="Stable Normal")
            
        st.markdown("### 🧬 Detailed Inspection Verdict")
        
        if prediction == 1:
            st.error(f"🚨 **CRITICAL SECURITY ALERT: Threat Signature Identified!**")
            
            # Determine the likely threat variant based on input configurations
            threat_variant = "Distributed Denial of Service (DDoS)" if user_packet_size > 7000 else "Brute-Force Authentication Attack"
            
            st.markdown(f"""
            * **Identified Attack Vector Type:** {threat_variant}
            * **Automated Firewall Action:** Ingested IP packet signature blacklisted dynamically from port registers.
            * **System Log Flag:** Captured and written into `network_logs` database instances.
            """)
            
            # Render a neat visual confidence breakdown chart
            chart_data = pd.DataFrame({'Probability %': [safe_prob, attack_prob]}, index=['Safe Traffic', 'Malicious Vector'])
            st.bar_chart(chart_data)
            
        else:
            st.success("✅ **Telemetry Clear: Traffic Flow Verified as Legitimate.**")
            st.markdown("""
            The analytical weights engine verified the ingestion packet dimensions and login tracking array structure. 
            No anomalous variations were detected. System operations continue on standard baseline.
            """)
            
            chart_data = pd.DataFrame({'Probability %': [safe_prob, attack_prob]}, index=['Safe Traffic', 'Malicious Vector'])
            st.bar_chart(chart_data)
            
    else:
        st.info("💡 **Ready for Input Telemetry:** Use the sidebar adjustment panel to simulate live network metrics, then press **'Run Forensic Analysis'** to execute real-time leak-proof ML pipe structures.")

# ==============================================================================
# TAB 2: TELEMETRY ANALYTICS MOCK MONITOR
# ==============================================================================
with tab_logs:
    st.subheader("📈 Ongoing Traffic Volume Statistics")
    st.write("Visual tracking logs matching standard SIEM interface profiles.")
    
    # Generate mock timeline sequence using standard line charts
    timeline_data = pd.DataFrame(
        np.random.randn(20, 2) * [10, 2] + [500, 2],
        columns=['Average Packet Size (Bytes)', 'Active Users Connection Count']
    )
    st.line_chart(timeline_data)
    
    with st.expander("ℹ️ How This Section Works in Full Production"):
        st.markdown("""
        In an enterprise deployment, this tab would write an active background thread connection utilizing a `SELECT` string to poll your SQL database table sequentially, keeping the metric panels updated automatically as new traffic logs flow inside the stack registers.
        """)

# ==============================================================================
# TAB 3: RESUME BULLET POINTS & PROFILE VALUE
# ==============================================================================
