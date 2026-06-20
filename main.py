import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
st.set_page_config(
    page_title="Forensic Log Analyzer Pro",
    page_icon="⚡",
    layout="wide"
)

st.markdown("""
    <style>
    .main { background-color: #0b0c10; color: #c5c6c7; }
    h1, h2, h3 { color: #66fcf1 !important; font-family: 'Courier New', Courier, monospace; }
    .stMetric { background-color: #1f2833; padding: 15px; border-radius: 5px; border: 1px solid #45a29e; }
    div.stDataFrame { border: 1px solid #45a29e; border-radius: 4px; }
    </style>
    """, unsafe_allow_html=True)

st.title("IPDR/CDR Forensic Link Analyzer")
st.markdown("---")

st.sidebar.header("Forensic Ingestion")
uploaded_file = st.sidebar.file_uploader("Upload Production Log (CSV)", type=["csv"])

df = None

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file, low_memory=False)
        st.sidebar.success(f"Loaded {len(df):,} entries successfully!")
    except Exception as e:
        st.sidebar.error(f"Inbound Read Error: {e}")
else:
    st.sidebar.info("Awaiting file upload. Drop your CSV dataset here.")
    if os.path.exists("test_case.csv"):
        df = pd.read_csv("test_case.csv")

if df is not None:
    rename_rules = {
        "Source": "Source_IP",
        "Source IP": "Source_IP",
        "Destination": "Destination_IP",
        "Destination IP": "Destination_IP",
        "Time": "Timestamp",
        "Time Stamp": "Timestamp"
    }
    df.rename(columns=rename_rules, inplace=True)
    
    required = {"Source_IP", "Destination_IP"}
    if not required.issubset(df.columns):
        st.error(f"❌ Structural Incompatibility. Log must contain Source and Destination columns. Identified: {list(df.columns)}")
    else:
        df.dropna(subset=["Source_IP", "Destination_IP"], inplace=True)
        
        noise_ips = ["255.255.255.255", "0.0.0.0", "localhost", "127.0.0.1"]
        df = df[~df["Source_IP"].isin(noise_ips) & ~df["Destination_IP"].isin(noise_ips)]
        
        TOTAL_ROWS = len(df)
        
        link_metrics = df.groupby(["Source_IP", "Destination_IP"]).size().reset_index(name="Hits")
        link_metrics = link_metrics.sort_values(by="Hits", ascending=False).reset_index(drop=True)
        
        col1, col2 = st.columns([4, 3])
        
        with col1:
            st.subheader("📊 High-Performance Link Interaction Matrix")
            st.caption("Top 20 absolute transactional tracking pathways plotted seamlessly.")
            
            top_plotted = link_metrics.head(20).copy()
            
            fig, ax = plt.subplots(figsize=(10, 6))
            fig.patch.set_facecolor('#1f2833')
            ax.set_facecolor('#1f2833')
            
            top_plotted["Link_Path"] = top_plotted["Source_IP"] + " ➔ " + top_plotted["Destination_IP"]
            sns.barplot(
                x="Hits", 
                y="Link_Path", 
                data=top_plotted, 
                ax=ax, 
                palette="mako",
                hue="Link_Path",
                legend=False
            )
            
            ax.tick_params(colors='white', labelsize=10)
            ax.xaxis.label.set_color('white')
            ax.yaxis.label.set_color('white')
            ax.set_xlabel("Total Logged Transactions (Hits)", fontsize=12, fontweight='bold')
            ax.set_ylabel("Suspect Communication Pathway", fontsize=12, fontweight='bold')
            ax.grid(color='#45a29e', linestyle='--', alpha=0.3)
            
            st.pyplot(fig)
            
        with col2:
            st.subheader("Target Priority Triage List")
            st.caption("Complete transmission density breakdown ranked mathematically.")
            
            st.dataframe(
                link_metrics.head(500),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Source_IP": "A-Party Address",
                    "Destination_IP": "B-Party Endpoint",
                    "Hits": "Total Audited Hits"
                }
            )
            
            st.markdown("---")
            st.subheader("Audited Statistics")
            m_col1, m_col2 = st.columns(2)
            m_col1.metric(label="Total Records Swept", value=f"{TOTAL_ROWS:,}")
            m_col2.metric(label="Distinct Intercept Links", value=f"{len(link_metrics):,}")

        # Raw Logs Inspection Panel at Footer (Capped at 2000 rows for view fluidness)
        st.markdown("---")
        st.subheader("Data Grid Inspection Frame (First 1,000 Records)")
        st.dataframe(df.head(1000), use_container_width=True)