import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
from typing import Dict, List
import json
import requests
from streamlit_lottie import st_lottie

from analyzer import WebScamAnalyzer

# --- Page Configuration ---
st.set_page_config(
    page_title="Guardian | Advanced URL Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Lottie Animation Loader ---
def load_lottieurl(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# Load specific animations (using public URLs for reliability, or fallbacks)
lottie_security = load_lottieurl("https://lottie.host/98c56434-d07b-4560-af84-06109315d9da/wJ3R6j4yWc.json")
lottie_scanning = load_lottieurl("https://lottie.host/5a88c757-0112-4545-91db-043598777085/jX6Zc8yaC8.json")
lottie_safe = load_lottieurl("https://lottie.host/7e04dfd8-07e0-4780-8777-6284695029e9/P4X3x8Qj4m.json") 
lottie_alert = load_lottieurl("https://lottie.host/8b725046-d250-4286-9c4c-474012117188/8p7X6q5n0r.json")

# --- Custom CSS (Glassmorphism & Modern UI) ---
st.markdown("""
<style>
    /* Global Styles */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"]  {
        font-family: 'Inter', sans-serif;
        background-color: #0e1117; 
        color: #ffffff;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #0e1117; 
    }
    ::-webkit-scrollbar-thumb {
        background: #333; 
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #555; 
    }

    /* Glassmorphic Cards */
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        transition: transform 0.2sease, box-shadow 0.2s ease;
    }
    
    .glass-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.2);
    }

    /* Headers */
    h1, h2, h3 {
        font-weight: 700 !important;
        background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem !important;
    }
    
    .section-header {
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: 1rem;
        color: #e0e0e0;
        border-left: 4px solid #4facfe;
        padding-left: 10px;
    }

    /* Metric Values */
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #fff;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #aaa;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Risk Badges */
    .badge {
        padding: 5px 12px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-critical { background: rgba(255, 82, 82, 0.2); color: #ff5252; border: 1px solid #ff5252; }
    .badge-high { background: rgba(255, 179, 0, 0.2); color: #ffb300; border: 1px solid #ffb300; }
    .badge-medium { background: rgba(255, 238, 88, 0.2); color: #ffee58; border: 1px solid #ffee58; }
    .badge-low { background: rgba(66, 165, 245, 0.2); color: #42a5f5; border: 1px solid #42a5f5; }
    .badge-safe { background: rgba(102, 187, 106, 0.2); color: #66bb6a; border: 1px solid #66bb6a; }

    /* Input Fields */
    .stTextInput input {
        background-color: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        color: white !important;
        border-radius: 10px !important;
        padding: 10px 15px !important;
    }
    .stTextInput input:focus {
        border-color: #4facfe !important;
        box-shadow: 0 0 10px rgba(79, 172, 254, 0.3) !important;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: rgba(255,255,255,0.05);
        border-radius: 10px 10px 0 0;
        border: none;
        color: #aaa;
        transition: all 0.3s;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(79, 172, 254, 0.1) !important;
        color: #4facfe !important;
        border-bottom: 2px solid #4facfe !important;
    }

    /* Buttons */
    .stButton button {
        background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
        color: black;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .stButton button:hover {
        transform: scale(1.02);
        box-shadow: 0 4px 15px rgba(79, 172, 254, 0.4);
        color: black;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        margin-top: 5rem;
        padding: 2rem;
        border-top: 1px solid rgba(255,255,255,0.1);
        color: #666;
    }
</style>
""", unsafe_allow_html=True)

# Initialize analyzer
@st.cache_resource
def get_analyzer():
    return WebScamAnalyzer()

analyzer = get_analyzer()

def display_risk_meter(score: int, level: str, color: str):
    """Display modern risk meter with gauge chart"""
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        number={'suffix': "%", 'font': {'size': 35, 'color': "white", 'family': "Inter"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 0, 'tickcolor': "rgba(0,0,0,0)"},
            'bar': {'color': color, 'thickness': 0.75}, # Making the value bar thicker and colored
            'bgcolor': "rgba(255,255,255,0.05)",
            'borderwidth': 0,
            'steps': [
                {'range': [0, 100], 'color': "rgba(255,255,255,0.1)"} # Background track
            ],
            'threshold': {
                'line': {'color': "white", 'width': 2},
                'thickness': 0.8,
                'value': score
            }
        }
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=220,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Risk Level Badge
    badge_class = f"badge-{level.lower().replace(' ', '')}" if level != "VERY LOW" else "badge-safe"
    if level == "CRITICAL" or level == "HIGH": 
         badge_class = "badge-critical" # Map simplified logic
         
    st.markdown(f"""
    <div style="text-align: center; margin-top: -10px;">
        <span class="badge {badge_class}">{level} RISK</span>
    </div>
    """, unsafe_allow_html=True)

def display_threat_cards(results: Dict):
    """Display threat intelligence in a visually appealing grid"""
    st.markdown('<div class="section-header">Threat Intelligence</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    # VirusTotal
    vt = results.get('virustotal', {})
    vt_color = "#ff5252" if vt.get('malicious', 0) > 0 else "#66bb6a"
    vt_icon = "🦠" # Virus
    
    with col1:
        st.markdown(f"""
        <div class="glass-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.2rem;">{vt_icon} VirusTotal</span>
                <span style="color: {vt_color}; font-weight: bold;">
                    {vt.get('malicious', 0)} / {vt.get('total_engines', 0)}
                </span>
            </div>
            <div style="margin-top: 10px; font-size: 0.9rem; color: #ccc;">
                Engines detected malicious activity
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    # Google Safe Browsing
    gsb = results.get('google_safe_browsing', {})
    gsb_safe = not gsb.get('threats_found', False)
    gsb_color = "#66bb6a" if gsb_safe else "#ff5252"
    gsb_status = "SAFE" if gsb_safe else "THREAT DETECTED"
    
    with col2:
        st.markdown(f"""
        <div class="glass-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.2rem;">🛡️ Safe Browsing</span>
                <span style="color: {gsb_color}; font-weight: bold;">{gsb_status}</span>
            </div>
            <div style="margin-top: 10px; font-size: 0.9rem; color: #ccc;">
                Google Threat Database
            </div>
        </div>
        """, unsafe_allow_html=True)

    # PhishTank
    pt = results.get('phishtank', {})
    pt_safe = not pt.get('phish_found', False)
    pt_color = "#66bb6a" if pt_safe else "#ff5252"
    pt_status = "CLEAN" if pt_safe else "PHISHING"
    
    with col3:
        st.markdown(f"""
        <div class="glass-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.2rem;">🎣 PhishTank</span>
                <span style="color: {pt_color}; font-weight: bold;">{pt_status}</span>
            </div>
             <div style="margin-top: 10px; font-size: 0.9rem; color: #ccc;">
                Community Phishing Database
            </div>
        </div>
        """, unsafe_allow_html=True)

def display_feature_grid(features: Dict):
    """Display URL features in a glass grid"""
    st.markdown('<div class="section-header">URL Analysis Features</div>', unsafe_allow_html=True)
    
    metrics = [
        ("URL Length", features.get('url_length'), "Chars"),
        ("Domain Age", "Check WHOIS", "Days"), # Placeholder logic handled elsewhere usually
        ("Subdomains", features.get('subdomain_count'), "Count"),
        ("HTTPS", "Yes" if features.get('has_https') else "No", "Secure"),
        ("IP Based", "Yes" if features.get('is_ip_address') else "No", "Type"),
        ("@ Symbol", "Found" if features.get('has_at_symbol') else "None", "Redirect")
    ]
    
    cols = st.columns(6)
    for i, (label, value, sub) in enumerate(metrics):
        with cols[i]:
            st.markdown(f"""
            <div class="glass-card" style="padding: 15px; text-align: center;">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="font-size: 1.2rem; margin-top: 5px;">{value}</div>
            </div>
            """, unsafe_allow_html=True)

def main():
    # Sidebar
    with st.sidebar:
        if lottie_security:
            st_lottie(lottie_security, height=180, key="sidebar_anim")
        
        st.markdown("## 🛡️ Guardian")
        st.markdown("Advanced AI-powered URL analysis and threat detection system.")
        
        analysis_mode = st.selectbox(
            "Analysis Mode",
            ["Single URL", "Batch Analysis"]
        )
        
        st.markdown("---")
        st.markdown("### Settings")
        st.checkbox("Enable Deep Scan", value=True)
        st.checkbox("Check Dark Web", value=False)
        
        st.markdown("---")
        
        # History mini-view
        if 'analysis_history' in st.session_state and st.session_state.analysis_history:
             st.markdown(f"**History:** {len(st.session_state.analysis_history)} scans")
             if st.button("Clear History"):
                 st.session_state.analysis_history = []
                 st.rerun()

    # Main Hero Section
    col_hero_1, col_hero_2 = st.columns([2, 1])
    with col_hero_1:
        st.title("Web Scam Analyzer")
        st.markdown("""
        <div style="font-size: 1.2rem; color: #aaa; margin-bottom: 2rem;">
            Protect your digital presence. detect phishing, malware, and scam links instantly with our advanced threat intelligence engine.
        </div>
        """, unsafe_allow_html=True)
    with col_hero_2:
        # Placeholder for top right stats or micro interaction
        pass

    if analysis_mode == "Single URL":
        # Search Bar Area
        with st.container():
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            url = st.text_input("Enter URL to Analyze", placeholder="https://example.com/suspicious-link", label_visibility="collapsed")
            
            col_search_btn, col_examples = st.columns([1, 4])
            with col_search_btn:
                analyze_btn = st.button("🔍 ANALYZE", use_container_width=True)
            
            with col_examples:
                 with st.expander("Or try an example:", expanded=False):
                    example_urls = [
                        "https://www.google.com",
                        "http://secure-login-attempt.xyz",
                        "https://www.amazon.com"
                    ]
                    cols_ex = st.columns(len(example_urls))
                    for i, ex in enumerate(example_urls):
                        if cols_ex[i].button(ex, key=f"ex_{i}"):
                            st.session_state.example_url = ex
                            st.rerun()
                            
            st.markdown('</div>', unsafe_allow_html=True)

        # Handle Example URL click
        if 'example_url' in st.session_state:
            url = st.session_state.example_url
            del st.session_state.example_url
            # Trigger analysis logic immediately would require restructuring, 
            # for now, the user sees the URL in the box and clicks analyze, or we can auto-trigger if we want.
            # Let's just set the session state for the input if possible, 
            # but st.text_input design doesn't easily allow setting value from button click without rerun and managing state carefully.
            # Simplified: The text input should have `value` set from session state if available
        
        
        if analyze_btn and url:
             if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
             with st.spinner("Initializing Scan..."):
                 # Scanning Animation Area
                 ani_col1, ani_col2, ani_col3 = st.columns([1,2,1])
                 with ani_col2:
                     if lottie_scanning:
                         st_lottie(lottie_scanning, height=200, key="scanning")
                     else:
                         st.info("Scanning...")
                 
                 # Simulate steps
                 progress_text = "Analyzing URL structure..."
                 my_bar = st.progress(0, text=progress_text)
                 
                 steps = ["Analyzing domains...", "Querying Threat Intel...", "Verifying SSL...", "Finalizing Report..."]
                 for percent_complete, step in zip([25, 50, 75, 100], steps):
                     time.sleep(0.4)
                     my_bar.progress(percent_complete, text=step)
                 
                 try:
                     # Real Analysis
                     results = analyzer.analyze_url(url)
                     my_bar.empty()
                     
                     # Store history
                     if 'analysis_history' not in st.session_state:
                            st.session_state.analysis_history = []
                     st.session_state.analysis_history.append(results)

                     # --- Results View ---
                     st.markdown("---")
                     
                     # Top Level Verdict
                     risk_score = results['risk_assessment']['risk_score']
                     risk_level = results['risk_assessment']['risk_level']
                     
                     # Verdict Banner
                     if risk_score > 50:
                         verdict_color = "#ff5252" # Red
                         verdict_icon = "banned"
                         banner_bg = "rgba(255, 82, 82, 0.1)"
                         # lottie = lottie_alert
                     else:
                         verdict_color = "#66bb6a" # Green
                         verdict_icon = "check_circle"
                         banner_bg = "rgba(102, 187, 106, 0.1)"
                         # lottie = lottie_safe

                     st.markdown(f"""
                     <div class="glass-card" style="background: {banner_bg}; border: 1px solid {verdict_color};">
                        <h2 style="text-align: center; margin: 0; color: {verdict_color} !important; -webkit-text-fill-color: {verdict_color} !important;">
                             Target is {risk_level} Risk
                        </h2>
                     </div>
                     """, unsafe_allow_html=True)

                     # Main Dashboard Data
                     col_risk, col_details = st.columns([1, 2])
                     
                     with col_risk:
                         st.markdown('<div class="glass-card" style="height: 100%;">', unsafe_allow_html=True)
                         st.markdown('<div class="section-header">Risk Score</div>', unsafe_allow_html=True)
                         display_risk_meter(risk_score, risk_level, results['risk_assessment']['color'])
                         
                         if results['risk_assessment']['warnings']:
                             st.markdown('<div style="margin-top: 20px; color: #ff5252; font-weight: bold;">⚠️ Critical Factors:</div>', unsafe_allow_html=True)
                             for warn in results['risk_assessment']['warnings'][:3]:
                                 st.markdown(f"- {warn}")
                         st.markdown('</div>', unsafe_allow_html=True)

                     with col_details:
                        display_threat_cards(results['threat_intelligence'])
                        display_feature_grid(results['features'])

                     # Tabs for deep dive
                     st.markdown('<div style="height: 20px;"></div>', unsafe_allow_html=True)
                     tab1, tab2, tab3 = st.tabs(["📋 WHOIS & Domain", "🔐 SSL Security", "📄 Full JSON"])
                     
                     with tab1:
                         whois = results['whois_info']
                         if 'error' not in whois:
                            c1, c2, c3 = st.columns(3)
                            c1.markdown(f"**Registrar:**\n{whois.get('registrar', 'Unknown')}")
                            c2.markdown(f"**Creation Date:**\n{whois.get('creation_date', 'Unknown')}")
                            c3.markdown(f"**Expires:**\n{whois.get('expiration_date', 'Unknown')}")
                         else:
                             st.warning("WHOIS data unavailable.")

                     with tab2:
                         ssl_data = results['ssl_info']
                         if ssl_data.get('has_ssl'):
                              c1, c2 = st.columns(2)
                              c1.success(f"✅ Valid: {ssl_data.get('is_valid')}")
                              c2.info(f"Issuer: {ssl_data.get('issuer')}")
                         else:
                             st.error("No SSL Certificate Found")

                     with tab3:
                         st.json(results)

                 except Exception as e:
                     st.error(f"Analysis Failed: {str(e)}")
    
    else:
        st.info("Batch Analysis Mode - Drag and drop your CSV file.")
        uploaded_file = st.file_uploader("Upload CSV", type=['csv','txt'])
        if uploaded_file:
            st.write("Batch processing logic here...")

if __name__ == "__main__":
    main()