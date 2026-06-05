import streamlit as st
import subprocess
import json
import os
import re
import matplotlib.pyplot as plt

# Set page config for professional branding
st.set_page_config(
    page_title="ReverseFlash: SecureStream",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Detect if we are running in root or gui folder and fix cwd
current_dir = os.getcwd()
if not os.path.exists(os.path.join(current_dir, 'gui')):
    parent_dir = os.path.dirname(current_dir)
    if os.path.exists(os.path.join(parent_dir, 'src')):
        os.chdir(parent_dir)

# Custom Styling injection - Premium Dark Mode
st.markdown("""
<style>
    /* Sleek slate-dark theme */
    .stApp {
        background-color: #0b0c10;
        color: #c5c6c7;
    }
    .main-header {
        background-color: #0b0c10;
        border-bottom: 1px solid #333333;
        padding: 20px 0;
        text-align: left;
        margin-bottom: 30px;
    }
    .main-title {
        color: #ffffff !important;
        font-family: 'Outfit', sans-serif;
        font-size: 2.2rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-bottom: 0px !important;
    }
    .main-subtitle {
        color: #ff3b3f !important;
        font-family: 'Inter', sans-serif;
        font-size: 0.9rem;
        margin-top: 5px;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }
    .compliance-pass {
        border: 1px solid #00ffcc;
        background-color: rgba(0, 255, 204, 0.02);
        border-radius: 6px;
        padding: 18px 24px;
        text-align: left;
        margin-bottom: 25px;
    }
    .compliance-fail {
        border: 1px solid #ff3b3f;
        background-color: rgba(255, 59, 63, 0.02);
        border-radius: 6px;
        padding: 18px 24px;
        text-align: left;
        margin-bottom: 25px;
    }
    .section-card {
        background-color: #12131a;
        border: 1px solid #2b2e3a;
        border-radius: 6px;
        padding: 18px;
        margin-bottom: 15px;
    }
    .severity-high {
        background-color: #ff3b3f;
        color: white;
        padding: 3px 8px;
        border-radius: 3px;
        font-weight: bold;
        font-size: 0.8rem;
        text-transform: uppercase;
    }
    .severity-medium {
        background-color: #ffa500;
        color: white;
        padding: 3px 8px;
        border-radius: 3px;
        font-weight: bold;
        font-size: 0.8rem;
        text-transform: uppercase;
    }
    .severity-low {
        background-color: #ffcc00;
        color: black;
        padding: 3px 8px;
        border-radius: 3px;
        font-weight: bold;
        font-size: 0.8rem;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)

# Application Header
st.markdown("""
<div class="main-header">
    <h1 class="main-title">ReverseFlash: SecureStream</h1>
    <div class="main-subtitle">Pre-Commit Compliance Center</div>
</div>
""", unsafe_allow_html=True)

# Sidebar configurations
st.sidebar.markdown("<h2 style='color:#ff3b3f; font-size: 1.4rem; letter-spacing: 0.5px;'>Control Panel</h2>", unsafe_allow_html=True)
demo_mode = st.sidebar.checkbox("Demo Mode (Simulated Vulnerabilities)", value=False, help="Simulate failing checks to test dashboard interface behavior.")

st.sidebar.markdown("---")
st.sidebar.markdown("""
### Compliance Requirements
1. **SAST (Bandit)**: Zero High-severity findings allowed in codebase.
2. **Dependency Audit**: Zero High or Medium vulnerabilities in package configurations.
3. **Version Pinning**: All dependencies must use strict version pinning (==).
""")
st.sidebar.markdown("---")
st.sidebar.info("Designed to check compliance locally, preserving cloud runner minutes and assuring pipeline deployment success.")

# Local scan logic functions
def run_bandit_scan():
    try:
        import sys
        # Resolve bandit executable relative to sys.executable to support local virtual environment runs
        python_dir = os.path.dirname(sys.executable)
        bandit_exe = "bandit.exe" if os.name == "nt" else "bandit"
        local_bandit = os.path.join(python_dir, bandit_exe)
        bandit_cmd = local_bandit if os.path.exists(local_bandit) else "bandit"

        # Execute Bandit on the src directory targeting json output
        result = subprocess.run(
            [bandit_cmd, "-r", "src/", "-f", "json"],
            capture_output=True,
            text=True,
            shell=True if os.name == 'nt' else False
        )
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                return data.get("results", []), None
            except json.JSONDecodeError:
                return [], f"Failed to parse Bandit JSON output. Raw stdout: {result.stdout[:300]}"
        else:
            return [], f"Bandit returned empty output. Stderr: {result.stderr}"
    except FileNotFoundError:
        return [], "Bandit executable not found. Please install it using requirements-gui.txt."
    except Exception as e:
        return [], f"Error executing Bandit: {str(e)}"

def run_safety_scan():
    import sys
    python_dir = os.path.dirname(sys.executable)
    safety_exe = "safety.exe" if os.name == "nt" else "safety"
    local_safety = os.path.join(python_dir, safety_exe)
    safety_cmd = local_safety if os.path.exists(local_safety) else "safety"

    try:
        # Run safety check on requirements.txt targeting json format
        result = subprocess.run(
            [safety_cmd, "check", "-r", "requirements.txt", "--json"],
            capture_output=True,
            text=True,
            shell=True if os.name == 'nt' else False
        )
        
        stdout_clean = result.stdout or ""
        
        # Clean up any potential warning headers printed by safety before the JSON block
        json_start = stdout_clean.find('{')
        if json_start != -1:
            stdout_clean = stdout_clean[json_start:]
            
        json_end = stdout_clean.rfind('}')
        if json_end != -1:
            stdout_clean = stdout_clean[:json_end+1]
            
        if stdout_clean.strip():
            try:
                data = json.loads(stdout_clean)
                raw_vulns = data.get("vulnerabilities", [])
                findings = []
                for v in raw_vulns:
                    pkg = v.get("package_name", "Unknown")
                    version = v.get("analyzed_version", "")
                    advisory = v.get("advisory", "")
                    cve = v.get("CVE", "N/A")
                    severity_obj = v.get("severity")
                    
                    sev = "HIGH"
                    if severity_obj:
                        if isinstance(severity_obj, dict):
                            sev = severity_obj.get("cvssv3", {}).get("base_severity", "HIGH")
                        elif isinstance(severity_obj, str):
                            sev = severity_obj
                    
                    findings.append({
                        "package": f"{pkg}=={version}",
                        "severity": str(sev).upper(),
                        "message": f"{cve}: {advisory}"
                    })
                return findings, None
            except json.JSONDecodeError:
                return [], f"Failed to parse Safety JSON output. Raw stdout snippet: {result.stdout[:300]}"
        else:
            if result.stderr:
                return [], f"Safety returned empty output. Stderr: {result.stderr[:300]}"
            return [], None
    except FileNotFoundError:
        return [], "Safety executable not found. Please ensure it is installed in requirements-gui.txt."
    except Exception as e:
        return [], f"Error executing Safety: {str(e)}"

def analyze_dependencies():
    req_file_path = "requirements.txt"
    findings = []
    if not os.path.exists(req_file_path):
        return [{"package": "N/A", "severity": "HIGH", "message": f"Dependency file '{req_file_path}' not found."}]
    
    with open(req_file_path, "r") as f:
        lines = f.readlines()
        
    # 1. Structural Checks (Strict Pinning checks)
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        if '==' in line:
            # We no longer hardcode version rules here; Safety checks them dynamically!
            continue
        elif any(op in line for op in ['>=', '<=', '>', '<', '~=']):
            parts = re.split(r'[>=<~]', line)
            package = parts[0].strip() if parts else line
            findings.append({
                "package": line,
                "severity": "MEDIUM",
                "message": f"Line {line_num}: Loose version pinning detected. Strict pinning (==) is required."
            })
        else:
            findings.append({
                "package": line,
                "severity": "HIGH",
                "message": f"Line {line_num}: Missing version pinning structure entirely."
            })
            
    # 2. Safety Vulnerability scan
    safety_findings, safety_err = run_safety_scan()
    if safety_err:
        findings.append({
            "package": "Safety Scan Error",
            "severity": "MEDIUM",
            "message": safety_err
        })
    else:
        findings.extend(safety_findings)
            
    return findings

# Mock findings for Demo Mode
def get_mock_findings():
    mock_bandit = [
        {
            "filename": "src/app.py",
            "line_number": 45,
            "issue_text": "Use of unsafe eval() detected. Possible remote code execution.",
            "issue_severity": "HIGH",
            "test_id": "B307"
        },
        {
            "filename": "src/app.py",
            "line_number": 22,
            "issue_text": "Hardcoded credential string found in auth module.",
            "issue_severity": "HIGH",
            "test_id": "B105"
        },
        {
            "filename": "src/app.py",
            "line_number": 12,
            "issue_text": "Binding to all interfaces (0.0.0.0) could expose the socket.",
            "issue_severity": "LOW",
            "test_id": "B104"
        }
    ]
    mock_deps = [
        {
            "package": "Jinja2==3.1.2",
            "severity": "HIGH",
            "message": "Line 2: CVE-2024-22195: Jinja2 < 3.1.3 contains sandbox escape flaws."
        },
        {
            "package": "requests",
            "severity": "MEDIUM",
            "message": "Line 8: Loose version pinning detected. Strict pinning (==) is required."
        }
    ]
    return mock_bandit, mock_deps

# Main execution panel
st.markdown("### Pre-Commit Control Center")
st.write("Ensure local modifications comply with standard pipeline security rules prior to code commit/push.")

execute_scans = st.button("Run Pre-Commit Scan Suite", use_container_width=True)

if execute_scans:
    with st.spinner("Executing Local DevSecOps Scan Suite..."):
        # Load or run scans
        if demo_mode:
            bandit_findings, _ = get_mock_findings()
            dep_findings = get_mock_findings()[1]
            bandit_err = None
        else:
            bandit_findings, bandit_err = run_bandit_scan()
            dep_findings = analyze_dependencies()

        # Count issues
        b_high = sum(1 for f in bandit_findings if f["issue_severity"] == "HIGH")
        b_medium = sum(1 for f in bandit_findings if f["issue_severity"] == "MEDIUM")
        b_low = sum(1 for f in bandit_findings if f["issue_severity"] == "LOW")

        d_high = sum(1 for f in dep_findings if f["severity"] == "HIGH")
        d_medium = sum(1 for f in dep_findings if f["severity"] == "MEDIUM")
        d_low = sum(1 for f in dep_findings if f["severity"] == "LOW")

        total_high = b_high + d_high
        total_medium = b_medium + d_medium
        total_low = b_low + d_low

        # Compliance Check Summary Card
        st.markdown("---")
        if total_high > 0 or total_medium > 0:
            st.markdown(f"""
            <div class="compliance-fail">
                <h3 style="color: #ff3b3f !important; margin:0; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">Compliance Failed</h3>
                <p style="margin: 8px 0 0 0; font-size:1rem; color:#c5c6c7;">
                    Found {total_high} High and {total_medium} Medium severity defects. Do not push to remote repository.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="compliance-pass">
                <h3 style="color: #00ffcc !important; margin:0; font-weight:600; text-transform:uppercase; letter-spacing:0.5px;">Compliance Passed</h3>
                <p style="margin: 8px 0 0 0; font-size:1rem; color:#c5c6c7;">
                    All local scans completed successfully. Safe to perform Git push operations.
                </p>
            </div>
            """, unsafe_allow_html=True)

        # Layout for Charts and Statistics
        col_metrics, col_chart = st.columns([1, 1])

        with col_metrics:
            st.markdown("### Scan Metrics")
            
            # Custom styled metric container - Clean & Flat
            st.markdown(f"""
            <div style="display: flex; gap: 15px; margin-bottom: 20px;">
                <div style="flex: 1; background-color: #12131a; border: 1px solid #ff3b3f; border-radius: 6px; padding: 15px;">
                    <div style="font-size: 0.8rem; font-weight: 600; color: #888888; text-transform: uppercase; letter-spacing: 0.5px;">High</div>
                    <div style="font-size: 2.2rem; font-weight: 700; color: #ff3b3f; margin-top: 5px;">{total_high}</div>
                </div>
                <div style="flex: 1; background-color: #12131a; border: 1px solid #ffa500; border-radius: 6px; padding: 15px;">
                    <div style="font-size: 0.8rem; font-weight: 600; color: #888888; text-transform: uppercase; letter-spacing: 0.5px;">Medium</div>
                    <div style="font-size: 2.2rem; font-weight: 700; color: #ffa500; margin-top: 5px;">{total_medium}</div>
                </div>
                <div style="flex: 1; background-color: #12131a; border: 1px solid #ffcc00; border-radius: 6px; padding: 15px;">
                    <div style="font-size: 0.8rem; font-weight: 600; color: #888888; text-transform: uppercase; letter-spacing: 0.5px;">Low</div>
                    <div style="font-size: 2.2rem; font-weight: 700; color: #ffcc00; margin-top: 5px;">{total_low}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("#### Performance Metrics")
            st.write(f"- Scanned files: {len(set(f['filename'] for f in bandit_findings)) if bandit_findings else 0}")
            st.write(f"- Bandit SAST findings: {len(bandit_findings)}")
            st.write(f"- Dependency vulnerabilities: {len(dep_findings)}")
            if bandit_err:
                st.warning(bandit_err)

        with col_chart:
            st.markdown("### Severity Distribution")
            
            # Setup Matplotlib pie/donut chart
            plt.rcParams['text.color'] = '#c5c6c7'
            plt.rcParams['axes.labelcolor'] = '#c5c6c7'
            
            fig, ax = plt.subplots(figsize=(5, 3.5))
            fig.patch.set_facecolor('#0b0c10')
            ax.set_facecolor('#0b0c10')
            
            sizes = [total_high, total_medium, total_low]
            labels = ['High', 'Medium', 'Low']
            colors = ['#ff3b3f', '#ffa500', '#ffcc00']
            
            non_zero = [(s, l, c) for s, l, c in zip(sizes, labels, colors) if s > 0]
            
            if non_zero:
                sizes_nz, labels_nz, colors_nz = zip(*non_zero)
                wedges, texts, autotexts = ax.pie(
                    sizes_nz, 
                    labels=labels_nz, 
                    autopct='%1.0f%%', 
                    colors=colors_nz, 
                    startangle=90, 
                    wedgeprops=dict(width=0.45, edgecolor='#0b0c10', linewidth=3)
                )
                for text in texts:
                    text.set_color('#c5c6c7')
                    text.set_fontsize(10)
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
                    autotext.set_fontsize(10)
            else:
                ax.text(0.5, 0.5, 'Zero Defects\nVerified', 
                        horizontalalignment='center', verticalalignment='center',
                        transform=ax.transAxes, fontsize=12, color='#00ffcc', fontweight='bold')
                ax.axis('off')
                
            st.pyplot(fig)

        # Tab layout for Detailed Scan reports
        st.markdown("---")
        st.markdown("### Detailed Vulnerability Breakdown")
        tab_bandit, tab_deps = st.tabs(["Bandit SAST Results", "Dependency Audit Results"])

        with tab_bandit:
            if not bandit_findings:
                st.success("No static analysis issues identified in the codebase.")
            else:
                for idx, issue in enumerate(bandit_findings, 1):
                    sev = issue["issue_severity"]
                    sev_class = "severity-high" if sev == "HIGH" else ("severity-medium" if sev == "MEDIUM" else "severity-low")
                    
                    st.markdown(f"""
                    <div class="section-card">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <span style="font-weight:600; font-size:1rem; color:#ffffff;">Finding {idx}: {issue['issue_text']}</span>
                            <span class="{sev_class}">{sev}</span>
                        </div>
                        <div style="font-size:0.9rem; color:#888888; line-height:1.5;">
                            <b>Location:</b> <code>{issue['filename']}</code> (Line {issue['line_number']})<br>
                            <b>Rule ID:</b> {issue.get('test_id', 'N/A')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

        with tab_deps:
            if not dep_findings:
                st.success("No dependency vulnerability issues identified in requirements.txt.")
            else:
                for idx, dep in enumerate(dep_findings, 1):
                    sev = dep["severity"]
                    sev_class = "severity-high" if sev == "HIGH" else ("severity-medium" if sev == "MEDIUM" else "severity-low")
                    
                    st.markdown(f"""
                    <div class="section-card">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <span style="font-weight:600; font-size:1rem; color:#ffffff;">Dependency Defect {idx}: {dep['package']}</span>
                            <span class="{sev_class}">{sev}</span>
                        </div>
                        <div style="font-size:0.9rem; color:#888888; line-height:1.5;">
                            <b>Advisory:</b> {dep['message']}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
else:
    st.info("Execute scans to run local audits.")
