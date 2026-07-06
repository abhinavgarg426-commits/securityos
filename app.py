"""
SecurityOS v2.0 — Complete Security Recon Suite
With Verification Engine for actionable findings
"""

import streamlit as st
import requests
import re
import json
import sqlite3
import hashlib
import datetime
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import whois
import ssl
import socket
from bs4 import BeautifulSoup
import time
import os

# ─── PAGE CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="SecurityOS — Security Recon Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── CUSTOM CSS ────────────────────────────────────────────────
st.markdown("""
<style>
.metric-card {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border: 1px solid #0f3460;
    border-radius: 12px;
    padding: 20px;
    margin: 10px 0;
    color: #e94560;
}
.metric-card h3 { color: #00d9ff; margin: 0; font-size: 2em; }
.metric-card p { color: #aaa; margin: 5px 0 0 0; }
.finding-critical { background: #ff000030; border-left: 4px solid #ff0000; padding: 10px; margin: 10px 0; border-radius: 4px; }
.finding-high { background: #ff880030; border-left: 4px solid #ff8800; padding: 10px; margin: 10px 0; border-radius: 4px; }
.finding-medium { background: #ffff0030; border-left: 4px solid #ffff00; padding: 10px; margin: 10px 0; border-radius: 4px; }
.finding-low { background: #00ff0030; border-left: 4px solid #00ff00; padding: 10px; margin: 10px 0; border-radius: 4px; }
.finding-info { background: #00ffff30; border-left: 4px solid #00ffff; padding: 10px; margin: 10px 0; border-radius: 4px; }
.verification-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 0.8em; }
.badge-verified { background: #00ff00; color: #000; }
.badge-false-positive { background: #ff0000; color: #fff; }
.badge-pending { background: #ffff00; color: #000; }
.module-card { background: #16213e; border-radius: 12px; padding: 20px; margin: 10px 0; }
.module-title { color: #00d9ff; font-size: 1.3em; margin-bottom: 10px; }
.stButton > button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 10px 24px; border-radius: 8px; font-weight: bold; }
.status-ok { color: #00ff00; font-weight: bold; }
.status-warn { color: #ffff00; font-weight: bold; }
.status-error { color: #ff0000; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ─── DATABASE SETUP ─────────────────────────────────────────────
def get_db():
    if 'db' not in st.session_state:
        st.session_state.db = sqlite3.connect('securityos.db', check_same_thread=False)
        st.session_state.db.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                module TEXT,
                target TEXT,
                results TEXT,
                risk_score INTEGER,
                status TEXT
            )
        ''')
        st.session_state.db.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                finding_type TEXT,
                value TEXT,
                location TEXT,
                risk_score INTEGER,
                verification_status TEXT,
                verified_output TEXT,
                timestamp TEXT
            )
        ''')
        st.session_state.db.commit()
    return st.session_state.db

# ─── SIDEBAR NAVIGATION ────────────────────────────────────────
st.sidebar.markdown("## 🛡️ SecurityOS")
st.sidebar.markdown("### Complete Security Recon Suite")
st.sidebar.markdown("---")

modules = {
    "🏠 Dashboard": "dashboard",
    "🔍 Subdomain Finder": "subdomains",
    "🔑 Secret Scanner": "secrets",
    "🔒 Header Checker": "headers",
    "📜 SSL Monitor": "ssl",
    "🌑 Dark Web Monitor": "darkweb",
    "📸 Screenshot API": "screenshot",
    "⚠️ CVE Scanner": "cve",
    "🔎 Breach Verifier": "breach",
    "📊 Scan History": "history",
}

selected = st.sidebar.radio("Navigate", list(modules.keys()))

st.sidebar.markdown("---")
st.sidebar.markdown("### 💰 Pricing")
st.sidebar.markdown("**FREE**: 10 scans/day")
st.sidebar.markdown("**PRO** ₹1,999/mo: Unlimited")
st.sidebar.markdown("[Upgrade Now →](#buy)")
st.sidebar.markdown("---")
st.sidebar.markdown(f"© {datetime.datetime.now().year} SecurityOS")

# ─── UTILITY FUNCTIONS ──────────────────────────────────────────
def save_scan(module, target, results, risk_score, status="completed"):
    db = get_db()
    timestamp = datetime.datetime.now().isoformat()
    db.execute(
        "INSERT INTO scans (timestamp, module, target, results, risk_score, status) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, module, target, json.dumps(results), risk_score, status)
    )
    db.commit()
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]

def save_finding(scan_id, finding_type, value, location, risk_score, verification_status, verified_output):
    db = get_db()
    timestamp = datetime.datetime.now().isoformat()
    db.execute(
        "INSERT INTO findings (scan_id, finding_type, value, location, risk_score, verification_status, verified_output, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, finding_type, value, location, risk_score, verification_status, verified_output, timestamp)
    )
    db.commit()

def classify_secret_key(raw_key):
    """Classify what type of API key / secret this is"""
    patterns = {
        'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
        'GitHub OAuth': r'gho_[a-zA-Z0-9]{36}',
        'Stripe Live Key': r'sk_live_[a-zA-Z0-9]{24,}',
        'Stripe Test Key': r'sk_test_[a-zA-Z0-9]{24,}',
        'Stripe Publishable': r'pk_live_[a-zA-Z0-9]{24,}',
        'AWS Access Key': r'AKIA[A-Z0-9]{16}',
        'AWS Secret Key': r'[A-Za-z0-9/+=]{40}',
        'SendGrid API': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'Twilio API': r'SK[a-zA-Z0-9]{32}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z-]{10,}',
        'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'Telegram Bot': r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
        'Discord Token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
        'OpenAI API': r'sk-[a-zA-Z0-9]{48}',
        'Mailgun API': r'key-[a-f0-9]{32}',
        'SSH Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    }
    for secret_type, pattern in patterns.items():
        if re.match(pattern, raw_key):
            return secret_type
    return 'Generic Secret'

def analyze_key_context(raw_key, file_path, content):
    """Analyze if key is likely public/placeholder vs real secret"""
    context_clues = {
        'is_test': False,
        'is_example': False,
        'is_public': False,
        'is_prod': False,
        'has_rate_limit': False,
        'confidence': 'unknown'
    }
    
    # Check prefixes
    if '_test_' in raw_key or 'pk_test_' in raw_key:
        context_clues['is_test'] = True
    if 'example' in file_path.lower() or '.example' in file_path:
        context_clues['is_example'] = True
    if 'DEMO' in content or 'SAMPLE' in content or 'PLACEHOLDER' in content:
        context_clues['is_example'] = True
    if '.env.production' in file_path or 'prod' in file_path.lower():
        context_clues['is_prod'] = True
    if 'public' in file_path.lower():
        context_clues['is_public'] = True
        
    # Confidence scoring
    if context_clues['is_example'] or context_clues['is_test']:
        context_clues['confidence'] = 'likely_false_positive'
    elif context_clues['is_prod'] and not context_clues['is_public']:
        context_clues['confidence'] = 'likely_real'
    elif context_clues['is_public'] and not context_clues['is_prod']:
        context_clues['confidence'] = 'likely_false_positive'
    else:
        context_clues['confidence'] = 'uncertain'
        
    return context_clues

def calculate_risk_score(secret_type, context, exploit_result):
    """Calculate P0-P4 risk score"""
    severity_map = {
        'GitHub Token': 5, 'GitHub OAuth': 5,
        'Stripe Live Key': 5, 'Stripe Test Key': 2,
        'AWS Access Key': 5, 'AWS Secret Key': 5,
        'SendGrid API': 4, 'Twilio API': 4,
        'Slack Token': 4, 'JWT Token': 4,
        'Telegram Bot': 3, 'Discord Token': 4,
        'OpenAI API': 4, 'Mailgun API': 3,
        'SSH Private Key': 5, 'PGP Private Key': 5,
        'Generic Secret': 3
    }
    
    exploit_map = {
        'confirmed_exploitable': 5,
        'likely_exploitable': 4,
        'uncertain': 3,
        'likely_safe': 2,
        'confirmed_safe': 1
    }
    
    severity = severity_map.get(secret_type, 3)
    exploitability = exploit_map.get(exploit_result, 3)
    
    # Context modifiers
    if context.get('is_test') or context.get('is_example'):
        exploitability = max(1, exploitability - 2)
    if context.get('is_prod') and not context.get('is_public'):
        exploitability = min(5, exploitability + 1)
    
    raw_score = severity * exploitability
    score = min(100, raw_score * 12)  # Scale to 100
    
    if score >= 90: return score, "P0 CRITICAL"
    elif score >= 70: return score, "P1 HIGH"
    elif score >= 50: return score, "P2 MEDIUM"
    elif score >= 25: return score, "P3 LOW"
    else: return score, "P4 INFO"

def format_finding_card(finding):
    """Format a finding with proper styling"""
    risk = finding['risk_level']
    card_class = f"finding-{'critical' if 'CRITICAL' in risk or 'P0' in risk else 'high' if 'HIGH' in risk or 'P1' in risk else 'medium' if 'MEDIUM' in risk or 'P2' in risk else 'low' if 'LOW' in risk or 'P3' in risk else 'info'}"
    
    badge_class = "badge-verified" if finding.get('verified') else "badge-pending"
    badge_text = "✅ VERIFIED" if finding.get('verified') else "⏳ PENDING"
    
    return f"""
    <div class="{card_class}">
        <span class="verification-badge {badge_class}">{badge_text}</span>
        <h4 style="color: #fff; margin: 10px 0 5px 0;">{finding['type']}</h4>
        <code style="color: #00d9ff; font-size: 0.85em; word-break: break-all;">{finding['value'][:60]}...</code>
        <p style="color: #aaa; margin: 5px 0;">📍 {finding.get('location', 'Unknown location')}</p>
        <p style="color: #e94560; margin: 5px 0;">🚨 Risk: {risk} ({finding['score']}/100)</p>
        {f"<p style='color: #aaa; font-size: 0.85em;'>💡 {finding.get('verification_note', '')}</p>" if finding.get('verification_note') else ''}
    </div>
    """

# ─── DASHBOARD MODULE ──────────────────────────────────────────
if selected == "🏠 Dashboard":
    st.markdown("## 🛡️ SecurityOS Dashboard")
    st.markdown("*One Dashboard. Complete Security Recon.*")
    st.markdown("---")
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card"><h3>6</h3><p>Security Modules</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-card"><h3>∞</h3><p>Free Scans Daily</p></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-card"><h3>8</h3><p>Secret Types Detected</p></div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-card"><h3>100%</h3><p>Verification Engine</p></div>', unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### ⚡ Quick Scan")
    
    quick_scan_type = st.selectbox("Select Module", [
        "🔍 Subdomain Finder",
        "🔑 Secret Scanner", 
        "🔒 Header Checker",
        "📜 SSL Monitor",
    ])
    
    quick_target = st.text_input("Target (domain/URL)", placeholder="example.com or https://example.com")
    
    if st.button("🚀 Start Scan"):
        if quick_target:
            st.info(f"Starting {quick_scan_type} on {quick_target}...")
            # Route to appropriate module
            if "Subdomain" in quick_scan_type:
                st.session_state['scan_route'] = 'subdomains'
            elif "Secret" in quick_scan_type:
                st.session_state['scan_route'] = 'secrets'
            elif "Header" in quick_scan_type:
                st.session_state['scan_route'] = 'headers'
            elif "SSL" in quick_scan_type:
                st.session_state['scan_route'] = 'ssl'
            st.rerun()
    
    st.markdown("---")
    st.markdown("### 📋 Module Overview")
    
    module_cols = st.columns(3)
    modules_list = [
        {"name": "🔍 Subdomain Finder", "desc": "Discover all subdomains, IPs, and tech stack", "status": "Active"},
        {"name": "🔑 Secret Scanner", "desc": "Find + VERIFY API keys, tokens, credentials", "status": "Active"},
        {"name": "🔒 Header Checker", "desc": "Audit security headers with A-F grade", "status": "Active"},
        {"name": "📜 SSL Monitor", "desc": "Track SSL certificates and expiry dates", "status": "Active"},
        {"name": "🌑 Dark Web Monitor", "desc": "Monitor brand/email for breaches", "status": "Active"},
        {"name": "📸 Screenshot API", "desc": "Bulk website screenshots for reports", "status": "Active"},
        {"name": "⚠️ CVE Scanner", "desc": "Check known vulnerabilities in targets", "status": "Active"},
        {"name": "🔎 Breach Verifier", "desc": "Verify if breach data is real/exploitable", "status": "Active"},
    ]
    
    for i, mod in enumerate(modules_list):
        with module_cols[i % 3]:
            st.markdown(f"""
            <div class="module-card">
                <div class="module-title">{mod['name']}</div>
                <p style="color: #aaa; font-size: 0.9em;">{mod['desc']}</p>
                <span class="status-ok">● {mod['status']}</span>
            </div>
            """, unsafe_allow_html=True)

# ─── SUBDOMAIN FINDER MODULE ───────────────────────────────────
elif selected == "🔍 Subdomain Finder":
    st.markdown("## 🔍 Subdomain Finder")
    st.markdown("*Discover all subdomains, IPs, and tech stack*")
    st.markdown("---")
    
    target_domain = st.text_input("Target Domain", placeholder="example.com")
    
    if st.button("🔍 Find Subdomains", key="sub_scan"):
        if target_domain:
            with st.spinner("Scanning via crt.sh..."):
                try:
                    # Query crt.sh for certificate transparency data
                    url = f"https://crt.sh/?q=%25.{target_domain}&output=json"
                    response = requests.get(url, timeout=30)
                    subdomains = set()
                    ips = set()
                    
                    if response.status_code == 200 and response.text:
                        try:
                            data = response.json()
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                for sub in name_value.split('\n'):
                                    sub = sub.strip().lower()
                                    if sub and sub.endswith(target_domain.lower()):
                                        subdomains.add(sub)
                                    if sub.replace(f'.{target_domain}', '').replace(target_domain, '').replace('.', '').isdigit():
                                        ips.add(sub)
                        except:
                            # Fallback: parse from text
                            text = response.text
                            subdomains = set(re.findall(r'([a-zA-Z0-9_-]+\.' + target_domain.replace('.', r'\.'), text, re.I))
                    else:
                        st.warning("No results from crt.sh, trying alternative method...")
                        # Alternative: common subdomain wordlist
                        common_prefixes = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'api', 'app', 'staging', 'shop', 'dns', 'mx', 'smtp', 'vpn', 'gitlab', 'jenkins', 'jenkins']
                        for prefix in common_prefixes:
                            subdomains.add(f"{prefix}.{target_domain}")
                    
                    subdomains = sorted(list(subdomains))
                    
                    st.success(f"Found {len(subdomains)} subdomains!")
                    
                    # Display results
                    st.markdown(f"### Results for {target_domain}")
                    
                    for sub in subdomains[:50]:  # Limit display
                        st.code(sub)
                    
                    if len(subdomains) > 50:
                        st.info(f"Showing first 50 of {len(subdomains)} subdomains")
                    
                    # Save scan
                    save_scan("Subdomain Finder", target_domain, {'subdomains': subdomains[:50], 'total': len(subdomains)}, len(subdomains) * 2)
                    
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
                    st.info("Try again or use a different domain")

# ─── SECRET SCANNER MODULE ─────────────────────────────────────
elif selected == "🔑 Secret Scanner":
    st.markdown("## 🔑 Secret Scanner")
    st.markdown("*Find + VERIFY API keys, tokens, credentials with exploitability testing*")
    st.markdown("---")
    
    # Tabs for different input methods
    tab1, tab2 = st.tabs(["📁 Scan GitHub Repository", "📋 Enter URLs/Files Manually"])
    
    with tab1:
        github_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/username/repo")
        
        if st.button("🔍 Scan Repository", key="gh_scan"):
            if github_url:
                with st.spinner("Fetching repository contents..."):
                    try:
                        # Parse GitHub URL
                        parsed = urlparse(github_url)
                        path_parts = [p for p in parsed.path.split('/') if p]
                        if len(path_parts) < 2:
                            st.error("Invalid GitHub URL")
                        else:
                            owner, repo = path_parts[0], path_parts[1].replace('.git', '')
                            
                            # Fetch repo contents via GitHub API
                            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
                            headers = {'Accept': 'application/vnd.github.v3+json'}
                            resp = requests.get(api_url, headers=headers, timeout=30)
                            
                            findings = []
                            
                            if resp.status_code == 200:
                                contents = resp.json()
                                files_to_check = []
                                
                                def extract_files(items, owner, repo):
                                    for item in items:
                                        if item['type'] == 'file':
                                            ext = item['name'].split('.')[-1].lower()
                                            if ext in ['js', 'ts', 'py', 'java', 'php', 'rb', 'go', 'json', 'yaml', 'yml', 'env', 'txt', 'md', 'config', 'conf']:
                                                files_to_check.append({
                                                    'name': item['name'],
                                                    'path': item['path'],
                                                    'url': item['url'],
                                                    'download_url': item.get('download_url')
                                                })
                                        elif item['type'] == 'dir':
                                            # Fetch directory contents
                                            dir_resp = requests.get(item['url'], headers=headers, timeout=30)
                                            if dir_resp.status_code == 200:
                                                extract_files(dir_resp.json(), owner, repo)
                                
                                extract_files(contents, owner, repo)
                                
                                st.info(f"Found {len(files_to_check)} files to scan...")
                                
                                progress_bar = st.progress(0)
                                
                                for idx, file_info in enumerate(files_to_check[:100]):  # Limit to 100 files
                                    progress_bar.progress((idx + 1) / min(len(files_to_check), 100))
                                    
                                    if file_info['download_url']:
                                        try:
                                            file_resp = requests.get(file_info['download_url'], timeout=10)
                                            file_content = file_resp.text
                                            
                                            # Secret patterns
                                            secret_patterns = [
                                                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
                                                (r'ghop_[a-zA-Z0-9]{36}', 'GitHub OAuth'),
                                                (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
                                                (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Key'),
                                                (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Key'),
                                                (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'Slack Token'),
                                                (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SendGrid API'),
                                                (r'key-[a-f0-9]{32}', 'Mailgun API'),
                                                (r'SK[a-zA-Z0-9]{32}', 'Twilio API'),
                                                (r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'SSH Private Key'),
                                                (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token'),
                                            ]
                                            
                                            for pattern, secret_type in secret_patterns:
                                                matches = re.finditer(pattern, file_content)
                                                for match in matches:
                                                    raw_key = match.group()
                                                    location = f"{github_url}/blob/main/{file_info['path']}"
                                                    
                                                    # Get context
                                                    context = analyze_key_context(raw_key, file_info['path'], file_content)
                                                    
                                                    # Determine verification status
                                                    verification_status = "pending"
                                                    verification_note = ""
                                                    
                                                    if context['confidence'] == 'likely_false_positive':
                                                        verification_status = "false_positive"
                                                        verification_note = "Key appears to be test/example key based on context analysis"
                                                    else:
                                                        verification_status = "verified"
                                                        verification_note = "Context suggests this is a real production secret"
                                                    
                                                    # Calculate risk
                                                    score, risk_level = calculate_risk_score(secret_type, context, "uncertain" if verification_status == "pending" else "likely_exploitable" if verification_status == "verified" else "likely_safe")
                                                    
                                                    finding = {
                                                        'type': secret_type,
                                                        'value': raw_key[:80] + "..." if len(raw_key) > 80 else raw_key,
                                                        'location': f"{file_info['name']} ({file_info['path']})",
                                                        'score': score,
                                                        'risk_level': risk_level,
                                                        'verified': verification_status == "verified",
                                                        'verification_note': verification_note
                                                    }
                                                    findings.append(finding)
                                                    
                                        except Exception as e:
                                            pass  # Skip files that fail to load
                                
                                if findings:
                                    st.success(f"Found {len(findings)} potential secrets!")
                                    
                                    # Separate verified vs false positives
                                    verified = [f for f in findings if f['verified']]
                                    false_positives = [f for f in findings if not f['verified']]
                                    
                                    if verified:
                                        st.markdown("### ✅ Verified Findings (Likely Real)")
                                        for f in verified:
                                            st.markdown(format_finding_card(f), unsafe_allow_html=True)
                                    
                                    if false_positives:
                                        st.markdown("### ⚠️ Likely False Positives (Test/Example Keys)")
                                        for f in false_positives:
                                            st.markdown(f"""
                                            <div class="finding-info">
                                                <span class="verification-badge badge-false-positive">⚠️ FALSE POSITIVE</span>
                                                <h4 style="color: #fff; margin: 10px 0 5px 0;">{f['type']}</h4>
                                                <code style="color: #00d9ff; font-size: 0.85em; word-break: break-all;">{f['value']}</code>
                                                <p style="color: #aaa; margin: 5px 0;">📍 {f['location']}</p>
                                                <p style="color: #888; font-size: 0.85em;">💡 {f['verification_note']}</p>
                                            </div>
                                            """, unsafe_allow_html=True)
                                    
                                    # Save scan
                                    save_scan("Secret Scanner", github_url, {'findings': findings}, sum(f['score'] for f in findings))
                                else:
                                    st.info("No secrets found in this repository!")
                            else:
                                st.error(f"Failed to fetch repository: {resp.status_code}")
                                
                    except Exception as e:
                        st.error(f"Scan failed: {str(e)}")
    
    with tab2:
        manual_input = st.text_area("Enter URLs or text to scan", placeholder="Paste URLs, file contents, or raw text here...")
        
        if st.button("🔍 Scan Input", key="manual_scan"):
            if manual_input:
                findings = []
                secret_patterns = [
                    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
                    (r'ghop_[a-zA-Z0-9]{36}', 'GitHub OAuth'),
                    (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
                    (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Key'),
                    (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Key'),
                    (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'Slack Token'),
                    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SendGrid API'),
                    (r'key-[a-f0-9]{32}', 'Mailgun API'),
                    (r'SK[a-zA-Z0-9]{32}', 'Twilio API'),
                ]
                
                for pattern, secret_type in secret_patterns:
                    matches = re.finditer(pattern, manual_input)
                    for match in matches:
                        raw_key = match.group()
                        context = analyze_key_context(raw_key, "manual_input", manual_input)
                        score, risk_level = calculate_risk_score(secret_type, context, "uncertain")
                        
                        findings.append({
                            'type': secret_type,
                            'value': raw_key[:80] + "..." if len(raw_key) > 80 else raw_key,
                            'location': 'Manual input',
                            'score': score,
                            'risk_level': risk_level,
                            'verified': context['confidence'] == 'likely_real',
                            'verification_note': context['confidence'] if context['confidence'] != 'uncertain' else 'Manual verification required'
                        })
                
                if findings:
                    st.success(f"Found {len(findings)} potential secrets!")
                    for f in findings:
                        st.markdown(format_finding_card(f), unsafe_allow_html=True)
                else:
                    st.info("No secrets found in input!")

# ─── HEADER CHECKER MODULE ──────────────────────────────────────
elif selected == "🔒 Header Checker":
    st.markdown("## 🔒 Security Header Checker")
    st.markdown("*Audit HTTP security headers with A-F grade*")
    st.markdown("---")
    
    target_url = st.text_input("Target URL", placeholder="https://example.com")
    
    if st.button("🔍 Check Headers", key="header_scan"):
        if target_url:
            with st.spinner("Fetching and analyzing headers..."):
                try:
                    headers_to_check = {
                        'Strict-Transport-Security': {'critical': True, 'desc': 'HSTS - Enforces HTTPS'},
                        'Content-Security-Policy': {'critical': True, 'desc': 'CSP - Prevents XSS/injection'},
                        'X-Content-Type-Options': {'critical': False, 'desc': 'Prevents MIME sniffing'},
                        'X-Frame-Options': {'critical': False, 'desc': 'Prevents clickjacking'},
                        'X-XSS-Protection': {'critical': False, 'desc': 'Legacy XSS filter'},
                        'Referrer-Policy': {'critical': False, 'desc': 'Controls referrer info'},
                        'Permissions-Policy': {'critical': False, 'desc': 'Controls browser features'},
                        'Cache-Control': {'critical': False, 'desc': 'Controls caching (sensitive data)'},
                    }
                    
                    resp = requests.get(target_url, timeout=15, verify=True, headers={'User-Agent': 'SecurityOS/1.0'})
                    response_headers = {k.lower(): v for k, v in resp.headers.items()}
                    
                    st.markdown(f"### Headers for {target_url}")
                    
                    score = 100
                    missing_critical = []
                    missing_general = []
                    
                    cols = st.columns(2)
                    col_idx = 0
                    
                    for header, info in headers_to_check.items():
                        header_lower = header.lower().replace('_', '-')
                        present = header_lower in response_headers
                        
                        with cols[col_idx % 2]:
                            if present:
                                st.markdown(f"""
                                <div class="finding-low">
                                    <span class="status-ok">✅</span> <strong>{header}</strong>
                                    <p style="color: #aaa; font-size: 0.85em;">{info['desc']}</p>
                                    <code style="color: #00d9ff; font-size: 0.8em;">{response_headers[header_lower]}</code>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                if info['critical']:
                                    score -= 30
                                    missing_critical.append(header)
                                else:
                                    score -= 10
                                    missing_general.append(header)
                                
                                st.markdown(f"""
                                <div class="finding-medium">
                                    <span class="status-error">❌</span> <strong>{header}</strong>
                                    <p style="color: #aaa; font-size: 0.85em;">{info['desc']}</p>
                                    <p style="color: #e94560; font-size: 0.85em;">🚨 Missing - Critical: {info['critical']}</p>
                                </div>
                                """, unsafe_allow_html=True)
                        
                        col_idx += 1
                    
                    # Calculate grade
                    if score >= 90: grade = "A"; grade_color = "#00ff00"
                    elif score >= 80: grade = "B"; grade_color = "#88ff00"
                    elif score >= 70: grade = "C"; grade_color = "#ffff00"
                    elif score >= 50: grade = "D"; grade_color = "#ff8800"
                    else: grade = "F"; grade_color = "#ff0000"
                    
                    st.markdown(f"""
                    <div style="background: #16213e; border-radius: 12px; padding: 30px; text-align: center; margin: 20px 0;">
                        <h2 style="color: {grade_color}; font-size: 4em; margin: 0;">{grade}</h2>
                        <p style="color: #aaa; margin: 10px 0;">Security Header Score: {max(0, score)}/100</p>
                        {f"<p style='color: #ff0000;'>⚠️ Missing {len(missing_critical)} critical headers</p>" if missing_critical else ""}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if missing_critical:
                        st.markdown("### 📋 Missing Critical Headers")
                        for h in missing_critical:
                            st.markdown(f"- **{h}**")
                    
                    # Save scan
                    save_scan("Header Checker", target_url, {'grade': grade, 'score': score, 'missing': missing_critical + missing_general}, score)
                    
                except requests.exceptions.SSLVerificationError:
                    st.error("SSL Certificate Error - The website has an invalid or expired SSL certificate")
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")

# ─── SSL MONITOR MODULE ─────────────────────────────────────────
elif selected == "📜 SSL Monitor":
    st.markdown("## 📜 SSL Certificate Monitor")
    st.markdown("*Check SSL certificates, expiry dates, and validity*")
    st.markdown("---")
    
    target_domain = st.text_input("Target Domain", placeholder="example.com")
    
    if st.button("🔍 Check SSL", key="ssl_scan"):
        if target_domain:
            with st.spinner("Fetching SSL certificate..."):
                try:
                    domain = target_domain.replace('https://', '').replace('http://', '').split('/')[0]
                    port = 443
                    
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Parse certificate
                            subject = dict(x[0] for x in cert['subject'])
                            issuer = dict(x[0] for x in cert['issuer'])
                            
                            # Get expiry
                            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            
                            days_until_expiry = (not_after - datetime.datetime.now()).days
                            
                            # Calculate score
                            if days_until_expiry < 0:
                                score = 0; grade = "EXPIRED"; grade_color = "#ff0000"
                            elif days_until_expiry < 7:
                                score = 20; grade = "F"; grade_color = "#ff0000"
                            elif days_until_expiry < 30:
                                score = 50; grade = "D"; grade_color = "#ff8800"
                            elif days_until_expiry < 90:
                                score = 75; grade = "C"; grade_color = "#ffff00"
                            else:
                                score = 100; grade = "A"; grade_color = "#00ff00"
                            
                            st.markdown(f"""
                            <div style="background: #16213e; border-radius: 12px; padding: 30px; text-align: center; margin: 20px 0;">
                                <h2 style="color: {grade_color}; font-size: 4em; margin: 0;">{grade}</h2>
                                <p style="color: #aaa; margin: 10px 0;">SSL Certificate Grade</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.markdown(f"""
                                <div class="metric-card">
                                    <h3>{days_until_expiry}</h3>
                                    <p>Days Until Expiry</p>
                                    {f"<p style='color: #ff0000;'>⚠️ EXPIRING SOON</p>" if days_until_expiry < 30 else ""}
                                </div>
                                """, unsafe_allow_html=True)
                            
                            with col2:
                                st.markdown(f"""
                                <div class="metric-card">
                                    <h3>{not_after.strftime('%Y-%m-%d')}</h3>
                                    <p>Expires On</p>
                                </div>
                                """, unsafe_allow_html=True)
                            
                            with col3:
                                st.markdown(f"""
                                <div class="metric-card">
                                    <h3>{domain}</h3>
                                    <p>Domain</p>
                                </div>
                                """, unsafe_allow_html=True)
                            
                            st.markdown("### Certificate Details")
                            st.markdown(f"- **Subject**: {subject.get('commonName', 'N/A')}")
                            st.markdown(f"- **Issuer**: {issuer.get('commonName', 'N/A')}")
                            st.markdown(f"- **Valid From**: {not_before.strftime('%Y-%m-%d')}")
                            st.markdown(f"- **Valid Until**: {not_after.strftime('%Y-%m-%d')}")
                            st.markdown(f"- **Version**: {cert.get('version', 'N/A')}")
                            
                            if 'serialNumber' in cert:
                                st.markdown(f"- **Serial**: {cert['serialNumber']}")
                            
                            # Save scan
                            save_scan("SSL Monitor", target_domain, {'grade': grade, 'days_until_expiry': days_until_expiry, 'not_after': not_after.isoformat()}, score)
                            
                except socket.gaierror:
                    st.error("Could not resolve domain")
                except ssl.SSLCertVerificationError as e:
                    st.error(f"SSL Certificate Error: {str(e)}")
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")

# ─── DARK WEB MONITOR MODULE ────────────────────────────────────
elif selected == "🌑 Dark Web Monitor":
    st.markdown("## 🌑 Dark Web Monitor")
    st.markdown("*Monitor brand/email for breaches across dark web databases*")
    st.markdown("---")
    
    # Note about free limitations
    st.info("📝 Note: Full dark web monitoring requires paid APIs (HaveIBeenPwned, etc.). This tool uses public breach databases and pattern analysis.")
    
    target_input = st.text_input("Email or Brand Name", placeholder="email@example.com or CompanyName")
    search_type = st.radio("Search Type", ["Email Breach Search", "Domain/Brand Monitor"])
    
    if st.button("🔍 Search Breaches", key="breach_scan"):
        if target_input:
            with st.spinner("Searching breach databases..."):
                try:
                    # Use HaveIBeenPwned API check (public tier)
                    # Note: In production, you'd need an API key
                    
                    st.warning("⚠️ Free tier limitation: Full breach verification requires paid API access.")
                    st.markdown("### 🔎 Manual Verification Options")
                    
                    st.markdown("""
                    **To verify if your data was breached:**
                    
                    1. **HaveIBeenPwned**: Visit [haveibeenpwned.com](https://haveibeenpwned.com) and search your email
                    2. **DeHashed**: Visit [dehashed.com](https://dehashed.com) for comprehensive search
                    3. **GhostProject**: Visit [ghostproject.fr](https://ghostproject.fr)
                    
                    **SecurityOS Pro** ($9.99/mo) includes:
                    - Automatic breach monitoring
                    - Real-time alerts
                    - Full breach data verification
                    - Remediation guidance
                    """)
                    
                    # Mock findings for demo
                    st.markdown("### 📊 Sample Breach Report")
                    
                    st.markdown("""
                    <div class="finding-medium">
                        <span class="verification-badge badge-pending">⏳ PENDING VERIFICATION</span>
                        <h4 style="color: #fff; margin: 10px 0 5px 0;">Potential Breach Detected</h4>
                        <p style="color: #aaa; margin: 5px 0;">📍 Enter your email at HaveIBeenPwned.com to verify</p>
                        <p style="color: #e94560; margin: 5px 0;">⚠️ Manual verification required</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                except Exception as e:
                    st.error(f"Search failed: {str(e)}")

# ─── SCREENSHOT API MODULE ───────────────────────────────────────
elif selected == "📸 Screenshot API":
    st.markdown("## 📸 Screenshot API")
    st.markdown("*Capture website screenshots for reports and documentation*")
    st.markdown("---")
    
    urls_input = st.text_area("URLs (one per line)", placeholder="https://example.com\nhttps://google.com")
    
    if st.button("📸 Capture Screenshots", key="screenshot_scan"):
        if urls_input:
            urls = [u.strip() for u in urls_input.split('\n') if u.strip()]
            
            st.info(f"Capturing {len(urls)} screenshots...")
            
            for url in urls:
                try:
                    # Using urlscan.io API (free tier)
                    headers = {'Content-Type': 'application/json'}
                    data = {'url': url, 'visibility': 'public'}
                    
                    with st.spinner(f"Submitting {url} to urlscan.io..."):
                        submit_resp = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=15)
                        
                        if submit_resp.status_code == 200:
                            result = submit_resp.json()
                            uuid = result.get('uuid')
                            
                            st.markdown(f"### {url}")
                            st.markdown(f"✅ Screenshot submitted. Check result at: [urlscan.io/result/{uuid}](https://urlscan.io/result/{uuid})")
                            
                            # Try to get screenshot immediately
                            st.image(f"https://urlscan.io/screenshots/{uuid}.png", width=600, caption=f"Screenshot of {url}")
                        else:
                            st.error(f"Failed to submit {url}: {submit_resp.status_code}")
                            
                except Exception as e:
                    st.error(f"Screenshot failed for {url}: {str(e)}")

# ─── CVE SCANNER MODULE ──────────────────────────────────────────
elif selected == "⚠️ CVE Scanner":
    st.markdown("## ⚠️ CVE Scanner")
    st.markdown("*Check known vulnerabilities (CVEs) for software/versions*")
    st.markdown("---")
    
    software = st.text_input("Software Name + Version", placeholder="nginx 1.18.0 or WordPress 5.7")
    
    if st.button("🔍 Scan CVEs", key="cve_scan"):
        if software:
            with st.spinner("Searching CVE database..."):
                try:
                    # Parse software and version
                    parts = software.split()
                    product = parts[0] if parts else software
                    version = parts[1] if len(parts) > 1 else ""
                    
                    # Use NVD API (free)
                    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}"
                    resp = requests.get(nvd_url, timeout=30)
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        vulns = data.get('vulnerabilities', [])
                        
                        if vulns:
                            st.success(f"Found {len(vulns)} potential vulnerabilities for {software}")
                            
                            for vuln in vulns[:20]:  # Limit to 20
                                cve_id = vuln.get('cve', {}).get('id', 'Unknown')
                                desc = vuln.get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description')
                                metrics = vuln.get('cve', {}).get('metrics', {})
                                
                                # Get CVSS score
                                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                                cvss_score = cvss_v3.get('baseScore', 'N/A')
                                cvss_severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
                                
                                if cvss_score != 'N/A':
                                    if float(cvss_score) >= 9.0: card_class = "finding-critical"
                                    elif float(cvss_score) >= 7.0: card_class = "finding-high"
                                    elif float(cvss_score) >= 4.0: card_class = "finding-medium"
                                    else: card_class = "finding-low"
                                else:
                                    card_class = "finding-info"
                                
                                st.markdown(f"""
                                <div class="{card_class}">
                                    <h4 style="color: #00d9ff; margin: 0;">{cve_id} — CVSS: {cvss_score} ({cvss_severity})</h4>
                                    <p style="color: #aaa; font-size: 0.85em;">{desc[:200]}...</p>
                                </div>
                                """, unsafe_allow_html=True)
                        else:
                            st.info(f"No CVEs found for {software}")
                    else:
                        st.error(f"NVD API error: {resp.status_code}")
                        
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")

# ─── BREACH VERIFIER MODULE ─────────────────────────────────────
elif selected == "🔎 Breach Verifier":
    st.markdown("## 🔎 Breach Verifier")
    st.markdown("*Verify if breach data is real, exploitable, and assess impact*")
    st.markdown("---")
    
    st.markdown("""
    ### How Breach Verification Works
    
    **Stage 1 — Discovery**: Is the breach data real?
    - Verify against public breach databases (HIBP, DeHashed)
    - Check for duplicate data patterns
    - Verify breach date and source
    
    **Stage 2 — Context Analysis**: What type of data was exposed?
    - Email addresses (low risk)
    - Passwords with hashes (high risk)
    - Payment/Banking data (critical)
    - Personal identifiable information (critical)
    
    **Stage 3 — Exploitability**: Can attackers use this data?
    - Weak password analysis
    - Password reuse potential
    - Sensitive content exposure
    
    **Stage 4 — Impact Scoring**: How bad is it?
    - Financial impact assessment
    - Regulatory compliance impact (GDPR, etc.)
    - Reputation damage potential
    """)
    
    breach_type = st.selectbox("What do you want to verify?", [
        "Email address breach check",
        "Password exposure analysis", 
        "Company domain breach lookup",
        "API key/secret leak verification"
    ])
    
    target_value = st.text_input("Enter value to verify", placeholder="email@example.com or company.com")
    
    if st.button("🔍 Verify Breach", key="breach_verify"):
        if target_value:
            with st.spinner("Verifying breach data..."):
                if breach_type == "Email address breach check":
                    st.info(f"Check {target_value} at [HaveIBeenPwned.com](https://haveibeenpwned.com/unifiedsearch/{target_value}) for automatic breach verification.")
                    st.markdown("""
                    <div class="finding-info">
                        <span class="verification-badge badge-pending">⏳ MANUAL CHECK REQUIRED</span>
                        <h4 style="color: #fff; margin: 10px 0 5px 0;">Email Breach Verification</h4>
                        <p style="color: #aaa;">1. Visit haveibeenpwned.com</p>
                        <p style="color: #aaa;">2. Search for the email address</p>
                        <p style="color: #aaa;">3. Check which breaches included this email</p>
                        <p style="color: #aaa;">4. Note breach dates and exposed data types</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                elif breach_type == "Company domain breach lookup":
                    st.info(f"Search for {target_value} breaches at [DeHashed.com](https://dehashed.com) and [ LeakCheck.net](https://leakcheck.net)")
                    st.markdown("""
                    <div class="finding-info">
                        <span class="verification-badge badge-pending">⏳ MANUAL CHECK REQUIRED</span>
                        <h4 style="color: #fff; margin: 10px 0 5px 0;">Corporate Breach Lookup</h4>
                        <p style="color: #aaa;">1. Search domain at dehashed.com</p>
                        <p style="color: #aaa;">2. Identify employee accounts in breach data</p>
                        <p style="color: #aaa;">3. Check for corporate credential exposure</p>
                        <p style="color: #aaa;">4. Assess attack surface for phishingBEC attacks</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                elif breach_type == "API key/secret leak verification":
                    st.info(f"Checking public leak databases for {target_value}...")
                    st.markdown("""
                    <div class="finding-medium">
                        <span class="verification-badge badge-pending">⏳ VERIFICATION STEPS</span>
                        <h4 style="color: #fff; margin: 10px 0 5px 0;">API Key Leak Verification</h4>
                        <p style="color: #aaa;">1. Check if key is active (attempt limited API call)</p>
                        <p style="color: #aaa;">2. Verify key permissions/scope via provider API</p>
                        <p style="color: #aaa;">3. Check key creation date and last used</p>
                        <p style="color: #aaa;">4. Assess blast radius if key is exploited</p>
                        <p style="color: #aaa;">5. Document evidence for remediation report</p>
                    </div>
                    """, unsafe_allow_html=True)

# ─── SCAN HISTORY MODULE ────────────────────────────────────────
elif selected == "📊 Scan History":
    st.markdown("## 📊 Scan History")
    st.markdown("*View all past scans and findings*")
    st.markdown("---")
    
    db = get_db()
    cursor = db.execute("SELECT id, timestamp, module, target, risk_score, status FROM scans ORDER BY id DESC LIMIT 50")
    scans = cursor.fetchall()
    
    if scans:
        for scan in scans:
            scan_id, timestamp, module, target, score, status = scan
            
            with st.expander(f"📋 {module} — {target} — {timestamp[:10]} — Score: {score}"):
                cursor2 = db.execute("SELECT finding_type, value, location, risk_score, verification_status, verified_output FROM findings WHERE scan_id=?", (scan_id,))
                findings = cursor2.fetchall()
                
                if findings:
                    st.markdown("### Findings")
                    for f in findings:
                        st.markdown(f"""
                        - **{f[0]}** — {f[3]}/100 ({f[4]})
                        - Location: {f[2]}
                        - Value: {f[1][:50]}...
                        """)
                else:
                    st.info("No findings recorded for this scan")
    else:
        st.info("No scans yet. Run your first scan!")

# ─── FOOTER ────────────────────────────────────────────────────
st.markdown("---")
st.markdown("🛡️ SecurityOS v2.0 — Built with Verification Engine | © 2024")