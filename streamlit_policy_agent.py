import streamlit as st
import time
import json
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Optional
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="Policy-Bounded AI Agent Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

@dataclass
class AgentAction:
    action_id: str
    description: str
    requires_permission: str
    risk_level: str
    needs_escalation: bool = False
    sensitive_data: bool = False

@dataclass
class PolicyResult:
    action: AgentAction
    status: str  # "approved", "denied", "escalated"
    reason: str
    timestamp: str

class PolicyEnforcementLayer:
    def __init__(self, policies: Dict[str, bool]):
        self.policies = policies
        self.audit_log = []
    
    def evaluate_action(self, action: AgentAction) -> PolicyResult:
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Check if permission is granted
        if not self.policies.get(action.requires_permission, False):
            result = PolicyResult(
                action=action,
                status="denied",
                reason=f"Policy '{action.requires_permission}' is disabled",
                timestamp=timestamp
            )
        elif action.needs_escalation and self.policies.get("require_escalation", True):
            result = PolicyResult(
                action=action,
                status="escalated",
                reason="Action requires human approval due to escalation policy",
                timestamp=timestamp
            )
        else:
            result = PolicyResult(
                action=action,
                status="approved",
                reason="Action meets all policy requirements",
                timestamp=timestamp
            )
        
        # Log the decision if audit logging is enabled
        if self.policies.get("audit_logging", False):
            self.audit_log.append({
                "timestamp": timestamp,
                "action": action.action_id,
                "status": result.status,
                "reason": result.reason,
                "risk_level": action.risk_level
            })
        
        return result

# Define cybersecurity scenarios
SCENARIOS = {
    "suspicious_login": {
        "title": "🔐 Suspicious Login Investigation",
        "description": "Multiple failed login attempts from IP 192.168.20.55 at 3:00 AM",
        "context": "Geographic anomaly: IP originates from a different country than user's typical location",
        "actions": [
            AgentAction("query_auth_logs", "Query authentication logs for suspicious IP", "read_logs", "low"),
            AgentAction("check_threat_intel", "Check IP reputation in threat intelligence feeds", "threat_intelligence", "low"),
            AgentAction("analyze_user_pattern", "Analyze user's typical login patterns", "read_logs", "medium"),
            AgentAction("block_ip", "Block suspicious IP address", "network_controls", "high", needs_escalation=True),
            AgentAction("disable_account", "Disable potentially compromised user account", "account_management", "high", needs_escalation=True),
            AgentAction("access_user_profile", "Access user HR profile for contact information", "hr_data_access", "medium", sensitive_data=True)
        ]
    },
    "malware_detection": {
        "title": "🦠 Malware Detection Response",
        "description": "Endpoint DESK-001 triggered malware signature 'Trojan.Win32.Generic'",
        "context": "Malware detected during routine scan, system still operational but potentially compromised",
        "actions": [
            AgentAction("query_endpoint_logs", "Retrieve endpoint activity and process logs", "read_logs", "low"),
            AgentAction("scan_file_hash", "Query malware hash in threat intelligence", "threat_intelligence", "low"),
            AgentAction("analyze_network_traffic", "Analyze network connections from infected endpoint", "network_monitoring", "medium"),
            AgentAction("isolate_endpoint", "Isolate endpoint from corporate network", "network_controls", "high", needs_escalation=True),
            AgentAction("quarantine_files", "Quarantine suspected malicious files", "endpoint_controls", "medium", needs_escalation=True),
            AgentAction("notify_user", "Send security alert to endpoint user", "communication", "low")
        ]
    },
    "data_exfiltration": {
        "title": "📤 Data Exfiltration Alert",
        "description": "Unusual large data transfer (2.5GB) to external IP 203.0.113.5",
        "context": "Transfer occurred outside business hours from finance department workstation",
        "actions": [
            AgentAction("analyze_transfer_logs", "Analyze data transfer patterns and volume", "read_logs", "medium"),
            AgentAction("check_destination_ip", "Verify reputation of destination IP address", "threat_intelligence", "low"),
            AgentAction("identify_data_types", "Classify types of data being transferred", "data_classification", "high", sensitive_data=True),
            AgentAction("block_external_ip", "Block traffic to suspicious external IP", "network_controls", "high", needs_escalation=True),
            AgentAction("preserve_evidence", "Create forensic image of source workstation", "forensics", "medium", needs_escalation=True),
            AgentAction("access_employee_records", "Review employee access rights and background", "hr_data_access", "high", sensitive_data=True, needs_escalation=True)
        ]
    },
    "insider_threat": {
        "title": "👤 Insider Threat Detection",
        "description": "Employee accessing sensitive files outside normal work hours and job scope",
        "context": "Marketing employee accessed finance database at 11:30 PM on weekend",
        "actions": [
            AgentAction("review_access_patterns", "Analyze employee's file access history", "read_logs", "medium"),
            AgentAction("check_authorization_matrix", "Verify if access aligns with job role", "access_control_review", "medium"),
            AgentAction("analyze_behavior_baseline", "Compare against normal behavior patterns", "behavior_analytics", "medium"),
            AgentAction("revoke_excess_permissions", "Remove unauthorized access privileges", "access_control_management", "high", needs_escalation=True),
            AgentAction("review_hr_records", "Access employee performance and disciplinary records", "hr_data_access", "high", sensitive_data=True, needs_escalation=True),
            AgentAction("initiate_investigation", "Begin formal insider threat investigation", "investigation", "high", needs_escalation=True)
        ]
    }
}

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'selected_scenario' not in st.session_state:
        st.session_state.selected_scenario = None
    if 'execution_results' not in st.session_state:
        st.session_state.execution_results = []
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []

def display_header():
    """Display the main header"""
    st.title("🛡️ Policy-Bounded AI Agent Simulator")
    st.markdown("### Experience how Policy Enforcement Layers control AI agent behavior in cybersecurity scenarios")
    
    with st.expander("ℹ️ About This Simulator"):
        st.markdown("""
        This simulator demonstrates the three-layer architecture of policy-bounded AI agents:
        
        1. **🧠 Reasoning Module**: The LLM generates a plan to address security incidents
        2. **🛡️ Policy Enforcement Layer (PEL)**: Validates each action against organizational policies  
        3. **⚡ Action Layer**: Executes only approved actions through secure APIs
        
        **Learning Objectives:**
        - Understand how policies constrain autonomous agent behavior
        - Experience the trade-offs between automation and control
        - See how audit logging enables compliance and accountability
        """)

def setup_sidebar():
    """Setup the sidebar with policy controls"""
    st.sidebar.header("🔧 Policy Configuration")
    
    st.sidebar.markdown("### Data Access Policies")
    policies = {}
    policies['read_logs'] = st.sidebar.checkbox("📋 Allow Security Log Access", value=True, help="Permits reading security and system logs")
    policies['threat_intelligence'] = st.sidebar.checkbox("🔍 Allow Threat Intelligence Queries", value=True, help="Access to external threat feeds and IP reputation services")
    policies['hr_data_access'] = st.sidebar.checkbox("👥 Allow HR Data Access", value=False, help="Access to employee personal information and records")
    
    st.sidebar.markdown("### Action Policies")
    policies['network_controls'] = st.sidebar.checkbox("🌐 Allow Network Controls", value=False, help="IP blocking, traffic filtering, network isolation")
    policies['account_management'] = st.sidebar.checkbox("👤 Allow Account Management", value=False, help="User account disable/enable, permission changes")
    policies['endpoint_controls'] = st.sidebar.checkbox("💻 Allow Endpoint Controls", value=False, help="Endpoint isolation, file quarantine, process termination")
    
    st.sidebar.markdown("### Governance Policies")
    policies['require_escalation'] = st.sidebar.checkbox("⚠️ Require Human Escalation", value=True, help="High-risk actions need human approval")
    policies['audit_logging'] = st.sidebar.checkbox("📝 Enable Audit Logging", value=True, help="Log all decisions for compliance")
    
    # Advanced policies
    with st.sidebar.expander("🔐 Advanced Policies"):
        policies['data_classification'] = st.sidebar.checkbox("📊 Allow Data Classification", value=False)
        policies['forensics'] = st.sidebar.checkbox("🔍 Allow Forensic Actions", value=False)
        policies['investigation'] = st.sidebar.checkbox("🕵️ Allow Investigation Initiation", value=False)
        policies['behavior_analytics'] = st.sidebar.checkbox("📈 Allow Behavior Analytics", value=True)
        policies['access_control_review'] = st.sidebar.checkbox("🔐 Allow Access Control Review", value=True)
        policies['access_control_management'] = st.sidebar.checkbox("⚙️ Allow Access Control Management", value=False)
        policies['network_monitoring'] = st.sidebar.checkbox("📡 Allow Network Monitoring", value=True)
        policies['communication'] = st.sidebar.checkbox("📢 Allow Communications", value=True)
    
    return policies

def display_scenario_selection():
    """Display scenario selection interface"""
    st.header("🎯 Security Scenario Selection")
    
    cols = st.columns(2)
    
    for i, (scenario_id, scenario) in enumerate(SCENARIOS.items()):
        col = cols[i % 2]
        with col:
            if st.button(scenario['title'], key=f"scenario_{scenario_id}", use_container_width=True):
                st.session_state.selected_scenario = scenario_id
                st.session_state.execution_results = []  # Clear previous results
                st.rerun()

def display_selected_scenario():
    """Display the selected scenario details"""
    if st.session_state.selected_scenario:
        scenario = SCENARIOS[st.session_state.selected_scenario]
        
        st.header(f"Selected: {scenario['title']}")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"**Incident Description:** {scenario['description']}")
            st.markdown(f"**Context:** {scenario['context']}")
        
        with col2:
            if st.button("🚀 Execute AI Agent", type="primary", use_container_width=True):
                execute_agent_simulation()

def execute_agent_simulation():
    """Execute the AI agent simulation with policy enforcement"""
    scenario = SCENARIOS[st.session_state.selected_scenario]
    policies = setup_sidebar()
    
    # Initialize Policy Enforcement Layer
    pel = PolicyEnforcementLayer(policies)
    
    # Clear previous results
    st.session_state.execution_results = []
    st.session_state.audit_logs = []
    
    # Show execution progress
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Step 1: Input Processing
    status_text.text("🔄 Step 1/4: Processing security incident input...")
    progress_bar.progress(25)
    time.sleep(1)
    
    # Step 2: Reasoning Module
    status_text.text("🔄 Step 2/4: AI reasoning module generating action plan...")
    progress_bar.progress(50)
    time.sleep(1)
    
    # Step 3: Policy Enforcement
    status_text.text("🔄 Step 3/4: Policy Enforcement Layer validating actions...")
    progress_bar.progress(75)
    
    results = []
    for action in scenario['actions']:
        result = pel.evaluate_action(action)
        results.append(result)
        time.sleep(0.2)  # Simulate processing time
    
    # Step 4: Execution
    status_text.text("🔄 Step 4/4: Executing approved actions...")
    progress_bar.progress(100)
    time.sleep(1)
    
    # Store results in session state
    st.session_state.execution_results = results
    st.session_state.audit_logs = pel.audit_log
    
    # Clear progress indicators
    progress_bar.empty()
    status_text.empty()
    
    st.rerun()

def display_results():
    """Display execution results and analysis"""
    if st.session_state.execution_results:
        st.header("📊 Execution Results")
        
        results = st.session_state.execution_results
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        approved = len([r for r in results if r.status == "approved"])
        denied = len([r for r in results if r.status == "denied"])
        escalated = len([r for r in results if r.status == "escalated"])
        total = len(results)
        
        col1.metric("✅ Approved", approved, delta=f"{approved/total*100:.1f}%")
        col2.metric("❌ Denied", denied, delta=f"{denied/total*100:.1f}%")
        col3.metric("⚠️ Escalated", escalated, delta=f"{escalated/total*100:.1f}%")
        col4.metric("📋 Total Actions", total)
        
        # Detailed results
        st.subheader("Detailed Action Results")
        
        for result in results:
            status_icon = {"approved": "✅", "denied": "❌", "escalated": "⚠️"}[result.status]
            status_color = {"approved": "green", "denied": "red", "escalated": "orange"}[result.status]
            
            with st.expander(f"{status_icon} {result.action.description}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"**Status:** :{status_color}[{result.status.upper()}]")
                    st.markdown(f"**Reason:** {result.reason}")
                    st.markdown(f"**Risk Level:** {result.action.risk_level.upper()}")
                    if result.action.sensitive_data:
                        st.markdown("**⚠️ Involves Sensitive Data**")
                
                with col2:
                    st.markdown(f"**Timestamp:** {result.timestamp}")
                    st.markdown(f"**Permission Required:** `{result.action.requires_permission}`")

def display_audit_logs():
    """Display audit logs if enabled"""
    if st.session_state.audit_logs:
        st.header("📋 Audit Logs")
        
        # Convert to DataFrame for better display
        df = pd.DataFrame(st.session_state.audit_logs)
        
        # Style the dataframe
        def style_status(val):
            colors = {"approved": "green", "denied": "red", "escalated": "orange"}
            return f"color: {colors.get(val, 'black')}"
        
        styled_df = df.style.applymap(style_status, subset=['status'])
        st.dataframe(styled_df, use_container_width=True)
        
        # Download audit logs
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download Audit Logs",
            data=csv,
            file_name=f"agent_audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def display_learning_exercises():
    """Display learning exercises and discussion questions"""
    st.header("🎓 Learning Exercises")
    
    with st.expander("💡 Policy Design Exercise"):
        st.markdown("""
        **Try these policy configurations and observe the differences:**
        
        1. **Conservative Setup**: Disable all action policies, keep only read access
           - *Question*: What can the agent accomplish? What are the limitations?
        
        2. **Balanced Setup**: Enable some actions but require escalation
           - *Question*: How does escalation change the response time vs. safety trade-off?
        
        3. **Aggressive Setup**: Enable all permissions, disable escalation
           - *Question*: What risks emerge? How might this impact security?
        """)
    
    with st.expander("🤔 Discussion Questions"):
        st.markdown("""
        **Reflect on these questions:**
        
        1. **Risk vs. Speed**: How do you balance autonomous response speed with security oversight?
        
        2. **Policy Gaps**: What happens when a scenario requires actions not covered by existing policies?
        
        3. **Multi-Agent Systems**: If multiple agents need to coordinate, how should policies be synchronized?
        
        4. **Audit Requirements**: What audit information would your organization need for compliance?
        """)

def main():
    """Main application function"""
    initialize_session_state()
    display_header()
    
    # Setup sidebar (this needs to be called to get policies)
    policies = setup_sidebar()
    
    # Main content area
    if not st.session_state.selected_scenario:
        display_scenario_selection()
    else:
        display_selected_scenario()
        display_results()
        
        if policies.get('audit_logging', False):
            display_audit_logs()
    
    # Always show learning exercises at the bottom
    st.divider()
    display_learning_exercises()
    
    # Footer
    st.markdown("---")
    st.markdown("*Policy-Bounded AI Agent Simulator - Educational Demo*")

if __name__ == "__main__":
    main()