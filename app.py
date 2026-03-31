import streamlit as st
import pandas as pd
import plotly.express as px

# --- 1. PAGE & STYLE CONFIGURATION ---
st.set_page_config(page_title="SHIELD-26 PRO | Smart SIEM", layout="wide")

st.markdown("""
    <style>
    .main { background-color: #0b0d11; color: #e6edf3; }
    .stMetric { border: 1px solid #30363d; padding: 15px; border-radius: 10px; background-color: #161b22; }
    h1, h2, h3 { color: #00ff41 !important; font-family: 'Segoe UI', Roboto, sans-serif; }
    .stAlert { background-color: #1a1111; border: 1px solid #f85149; }
    .css-1kyxreq { justify-content: center; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. THE SMART PRIORITIZATION ENGINE (BACK-END) ---
def analyze_logs_smart(df):
    threats = []
    # Best Practice 2026: Identity-First & Process-Based Scoring
    VIP_USERS = ['admin', 'cfo', 'ceo', 'root', 'it_dept']
    SENSITIVE_PROCESSES = ['powershell', 'cmd.exe', 'certutil', 'net.exe', 'bash']
    SHADOW_AI_DOMAINS = ['unknown-ai', 'free-chat-gpt', 'deep-fake-gen']

    for index, row in df.iterrows():
        risk_score = 0
        reasons = []

        # GAP 1: Identity/Impossible Travel Check
        # (Logic: If location is not the usual 'Office' or 'Home')
        if str(row.get('Location', '')).lower() not in ['office', 'home', 'internal']:
            risk_score += 40
            reasons.append("Unusual Location Access")

        # GAP 2: Shadow AI / Data Leakage
        dest = str(row.get('Destination', '')).lower()
        if any(domain in dest for domain in SHADOW_AI_DOMAINS) and row.get('Data_MB', 0) > 10:
            risk_score += 35
            reasons.append(f"Unauthorized AI Data Transfer ({row['Data_MB']}MB)")

        # GAP 3: SIEM Misjudgment / LotL (Living off the Land)
        proc = str(row.get('Process', '')).lower()
        if any(p in proc for p in SENSITIVE_PROCESSES):
            risk_score += 20
            reasons.append(f"Sensitive Binary Execution: {proc}")

        # Impact Multiplier: Is this a VIP user?
        user = str(row.get('User', '')).lower()
        if any(vip in user for vip in VIP_USERS):
            risk_score += 25
            reasons.append("VIP/Admin Account Involvement")

        # Categorize by Risk Score
        if risk_score >= 80:
            level = "CRITICAL"
            color = "🔴"
        elif risk_score >= 50:
            level = "HIGH"
            color = "🟠"
        elif risk_score >= 20:
            level = "MEDIUM"
            color = "🟡"
        else:
            continue # Ignore low-risk noise for clarity

        threats.append({
            "Priority": level,
            "Indicator": color,
            "Score": min(risk_score, 100), # Cap at 100
            "User": row['User'],
            "Summary": " | ".join(reasons),
            "Time": row.get('Time', 'N/A')
        })
            
    # Sort by Score so the most dangerous threats are at the top
    return sorted(threats, key=lambda x: x['Score'], reverse=True)

# --- 3. THE USER INTERFACE (FRONT-END) ---
st.title("🛡️ SHIELD-26: SMART THREAT HUNTER")
st.write("Solving modern SIEM gaps through Identity Context & Behavioral Scoring.")

# Sidebar for Data Ingestion
st.sidebar.image("https://img.icons8.com/nolan/64/security-shield.png")
st.sidebar.header("Log Ingestion")
uploaded_file = st.sidebar.file_uploader("Upload SIEM Logs (CSV)", type="csv")

# Load Data (Real or Mock)
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.sidebar.success("Logs Loaded Successfully!")
else:
    # High-quality Mock Data to demonstrate the Smart Prioritization
    df = pd.DataFrame([
        {"Time": "14:00", "User": "cfo@company.com", "Location": "Russia", "Event": "Login", "Data_MB": 0, "Destination": "Internal", "Process": "Explorer", "Severity": "Info"},
        {"Time": "14:05", "User": "intern_01", "Location": "Home", "Event": "Upload", "Data_MB": 85, "Destination": "free-chat-gpt.xyz", "Process": "Chrome", "Severity": "Low"},
        {"Time": "14:10", "User": "admin_main", "Location": "Office", "Event": "Exec", "Data_MB": 2, "Destination": "Local", "Process": "powershell.exe -bypass", "Severity": "Low"},
        {"Time": "14:20", "User": "marketing_staff", "Location": "Office", "Event": "Browse", "Data_MB": 5, "Destination": "google.com", "Process": "Edge", "Severity": "Info"}
    ])
    st.sidebar.info("Displaying Mock Data. Upload a CSV to analyze your network.")

# --- 4. DASHBOARD EXECUTION ---
threat_list = analyze_logs_smart(df)

# Metrics Bar
m1, m2, m3 = st.columns(3)
m1.metric("Total Events Analyzed", len(df))
m2.metric("Critical Threats Found", len([t for t in threat_list if t['Priority'] == "CRITICAL"]))
m3.metric("Avg Risk Score", f"{int(sum(t['Score'] for t in threat_list)/len(threat_list)) if threat_list else 0}%")

st.divider()

# Split Screen: Alerts vs Visualization
left_col, right_col = st.columns([3, 2])

with left_col:
    st.subheader("🎯 Prioritized Threat Feed")
    if not threat_list:
        st.success("System Clear: No threats identified above the noise threshold.")
    else:
        for t in threat_list:
            with st.expander(f"{t['Indicator']} {t['Priority']} (Score: {t['Score']}) - {t['User']}"):
                st.write(f"**Timestamp:** {t['Time']}")
                st.write(f"**Detection Reasons:** {t['Summary']}")
                if st.button(f"Isolate User {t['User']}", key=t['User']+t['Time']):
                    st.warning(f"ACTION SENT: User {t['User']} credentials suspended in Active Directory.")

with right_col:
    st.subheader("📊 Risk Distribution")
    if threat_list:
        threat_df = pd.DataFrame(threat_list)
        fig = px.pie(threat_df, names='Priority', values='Score', 
                     color_discrete_map={'CRITICAL':'#ff4b4b', 'HIGH':'#ffa500', 'MEDIUM':'#ffff00'},
                     hole=0.4)
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color="white")
        st.plotly_chart(fig, use_container_width=True)

st.subheader("📋 Ingested Log Audit Trail")
st.dataframe(df, use_container_width=True)
