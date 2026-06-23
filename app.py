import streamlit as st
import pandas as pd
import joblib
import numpy as np

# 1. Page Configuration Setup
st.set_page_config(page_title="Cyber Threat Detection SOC", layout="wide")

st.title("🛡️ Enterprise AI Cyber-Forensics SIEM Engine")
st.write("This live production dashboard loads a serialized Scikit-learn Pipeline to classify network log traffic in real-time.")

st.markdown("---")

# 2. Load the Saved Model Brain Safely
@st.cache_resource
def load_security_brain():
    # This loads BOTH the scaling/encoding rules and the Random Forest weights
    return joblib.load("security_pipeline_model.pkl")

production_pipeline = load_security_brain()

# 3. Create Sidebar for Live Network Input Emulation
st.sidebar.header("📥 Live Network Packet Ingestion")

user_protocol = st.sidebar.selectbox(
    "Select Network Protocol Type",
    options=['HTTP', 'TCP', 'UDP']
)

user_packet_size = st.sidebar.number_input(
    "Ingested Packet Size (Bytes)",
    min_value=64,
    max_value=50000,
    value=500,
    step=100,
    help="DDoS attacks typically flood the server with massive, multi-kilobyte packets."
)

user_logins = st.sidebar.slider(
    "Sequential Login Attempts (Last 5 Mins)",
    min_value=0,
    max_value=20,
    value=1,
    help="Brute force authentication attacks generate rapid, consecutive login attempts."
)

# 4. Trigger Analysis Process on Button Click
if st.sidebar.button("🔍 Run Forensic Packet Analysis", use_container_width=True):
    
    # CRITICAL: Put the inputs into a 2D Pandas DataFrame matching the exact training column names
    live_input_row = pd.DataFrame({
        'protocol_type': [user_protocol],
        'packet_size_bytes': [user_packet_size],
        'login_attempts': [user_logins]
    })
    
    # 5. Let the pipeline clean, transform, and evaluate the row automatically
    prediction = production_pipeline.predict(live_input_row)[0]
    probabilities = production_pipeline.predict_proba(live_input_row)[0]
    
    # Extract structural probability scores
    safe_probability = probabilities[0] * 100
    attack_probability = probabilities[1] * 100
    
    # 6. Render Dynamic UI Outputs based on Threat Risk State
    st.subheader("📊 Forensic Analytics Output Summary")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="Threat Confidence Level", value=f"{attack_probability:.2f}%")
    with col2:
        st.metric(label="Safe Traffic Margin", value=f"{safe_probability:.2f}%")
        
    if prediction == 1:
        st.error(f"🚨 **RED ALERT: Malicious Packet Signature Identified!**")
        st.markdown(f"""
        **System Integrity Warning:** The model analyzed the incoming data structures and flagged this request as an anomaly attack vectors patterns. 
        * **Target Action:** Blocked source IP from reaching database ports.
        """)
    else:
        st.success("✅ **Traffic Verified: Connection Secure.**")
        st.markdown("The system telemetry matches standardized safe user behavior logs. No actions required.")

else:
    # Initial landing view before user pushes the analysis button
    st.info("💡 Adjust the network parameters in the left sidebar configuration panel and click **'Run Forensic Packet Analysis'** to execute real-time pipeline inference.")