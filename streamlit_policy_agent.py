import uuid
from datetime import datetime

import streamlit as st
from sqlalchemy import create_engine, text

# =============================
# DB: Neon Postgres via SQLAlchemy
# =============================
# Requires Streamlit Secrets:
# [db]
# url = "postgresql+psycopg2://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require"
ENGINE = create_engine(
    st.secrets["db"]["url"],
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

def exec_sql(sql: str, **params):
    """Execute SQL with automatic transaction handling."""
    with ENGINE.begin() as conn:
        return conn.execute(text(sql), params)

def init_db_pg():
    """Create namespaced policies + audit tables if they don't exist."""
    exec_sql("""
    CREATE TABLE IF NOT EXISTS policies (
        namespace TEXT NOT NULL,
        key       TEXT NOT NULL,
        value     TEXT NOT NULL,
        PRIMARY KEY (namespace, key)
    )
    """)
    exec_sql("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id        BIGSERIAL PRIMARY KEY,
        namespace TEXT NOT NULL,
        ts        TEXT NOT NULL,
        scenario  TEXT NOT NULL,
        action    TEXT NOT NULL,
        allowed   INTEGER NOT NULL,
        params    TEXT,
        reason    TEXT
    )
    """)

# =============================
# Anonymous per-session namespace (no IDs)
# =============================
def get_namespace() -> str:
    # Use ?ns=... if present, otherwise create a random one and write it to the URL
    qs = st.experimental_get_query_params()
    ns = (qs.get("ns", [""])[0]).strip()
    if not ns:
        if "ns" not in st.session_state:
            st.session_state["ns"] = f"sess-{uuid.uuid4().hex[:8]}"
        ns = st.session_state["ns"]
        try:
            # Persist in the URL so the session is bookmark/share friendly
            st.experimental_set_query_params(ns=ns)
        except Exception:
            pass
    return ns

NS = get_namespace()  # global namespace token for this visitor/session

# =============================
# Namespaced policy helpers
# =============================
DEFAULTS_DISABLED = {
    "allow_log_access": "false",
    "allow_network_controls": "false",
    "allow_account_management": "false",
    "allow_endpoint_isolation": "false",
    "require_human_approval": "false",
    "audit_logging": "true",  # keep logging on so learners can see decisions
}

def get_policies_ns() -> dict[str, str]:
    rows = exec_sql(
        "SELECT key, value FROM policies WHERE namespace=:ns",
        ns=NS
    ).fetchall()
    return {k: v for (k, v) in rows}

def set_policy_ns(key: str, value: str):
    exec_sql("""
    INSERT INTO policies(namespace, key, value)
    VALUES (:ns, :k, :v)
    ON CONFLICT (namespace, key) DO UPDATE SET value = EXCLUDED.value
    """, ns=NS, k=key, v=value)

def reset_all_policies_to_disabled_ns():
    for k, v in DEFAULTS_DISABLED.items():
        set_policy_ns(k, v)

# =============================
# Namespaced audit helpers
# =============================
def log_decision(scenario: str, action: str, allowed: bool, params: str = "", reason: str = ""):
    pol = get_policies_ns()
    if pol.get("audit_logging", "true").lower() != "true":
        return
    exec_sql("""
    INSERT INTO audit_log(namespace, ts, scenario, action, allowed, params, reason)
    VALUES (:ns, :ts, :sc, :ac, :alw, :pa, :re)
    """,
    ns=NS,
    ts=datetime.utcnow().isoformat(timespec="seconds")+"Z",
    sc=scenario, ac=action, alw=1 if allowed else 0, pa=params, re=reason)

def read_audit_ns(limit: int = 100):
    return exec_sql("""
    SELECT ts, scenario, action, allowed, params, reason
    FROM audit_log
    WHERE namespace = :ns
    ORDER BY id DESC
    LIMIT :lim
    """, ns=NS, lim=limit).fetchall()

def clear_audit_ns():
    exec_sql("DELETE FROM audit_log WHERE namespace = :ns", ns=NS)

# =============================
# Policy enforcement
# =============================
def require_approval() -> bool:
    pol = get_policies_ns()
    return pol.get("require_human_approval", "false").lower() == "true"

def check_policy(action: str) -> tuple[bool, str]:
    if require_approval():
        return False, "Blocked: require_human_approval=true"
    pol = get_policies_ns()
    if action == "logs.search":
        ok = pol.get("allow_log_access", "false").lower() == "true"
        return ok, "Allowed by allow_log_access" if ok else "Blocked by allow_log_access=false"
    if action == "network.block_ip":
        ok = pol.get("allow_network_controls", "false").lower() == "true"
        return ok, "Allowed by allow_network_controls" if ok else "Blocked by allow_network_controls=false"
    if action == "account.disable":
        ok = pol.get("allow_account_management", "false").lower() == "true"
        return ok, "Allowed by allow_account_management" if ok else "Blocked by allow_account_management=false"
    if action == "endpoint.isolate":
        ok = pol.get("allow_endpoint_isolation", "false").lower() == "true"
        return ok, "Allowed by allow_endpoint_isolation" if ok else "Blocked by allow_endpoint_isolation=false"
    return False, "Unknown action"

# =============================
# Tools (simulated) — no context
# =============================
def tool_logs_search(scenario_name: str) -> str:
    ok, why = check_policy("logs.search")
    log_decision(scenario_name, "logs.search", ok, reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return "Found suspicious log entries. (simulated)"

def tool_block_ip(scenario_name: str) -> str:
    ok, why = check_policy("network.block_ip")
    log_decision(scenario_name, "network.block_ip", ok, reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return "✅ Blocked malicious IP address. (simulated)"

def tool_disable_account(scenario_name: str) -> str:
    ok, why = check_policy("account.disable")
    log_decision(scenario_name, "account.disable", ok, reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return "✅ Disabled compromised account. (simulated)"

def tool_isolate_endpoint(scenario_name: str) -> str:
    ok, why = check_policy("endpoint.isolate")
    log_decision(scenario_name, "endpoint.isolate", ok, reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return "✅ Isolated infected endpoint. (simulated)"

# =============================
# Scenarios (no context)
# =============================
SCENARIOS = {
    "brute_force": {
        "title": "Brute-force login from foreign IP",
        "description": "Multiple failed login attempts detected for a user account.",
        "playbook": [
            ("logs.search", "Search logs", lambda: tool_logs_search("Brute-force")),
            ("network.block_ip", "Block offending IP", lambda: tool_block_ip("Brute-force")),
            ("account.disable", "Disable account", lambda: tool_disable_account("Brute-force")),
        ],
    },
    "malware_endpoint": {
        "title": "Malware detected on endpoint",
        "description": "EDR flagged malware on workstation; lateral movement suspected.",
        "playbook": [
            ("endpoint.isolate", "Isolate endpoint", lambda: tool_isolate_endpoint("Malware")),
            ("logs.search", "Search logs for IOCs", lambda: tool_logs_search("Malware")),
        ],
    },
    "phishing": {
        "title": "Phishing reported by employee",
        "description": "User reported a suspicious email with a credential-harvesting link.",
        "playbook": [
            ("logs.search", "Search mail logs", lambda: tool_logs_search("Phishing")),
            ("account.disable", "Disable account", lambda: tool_disable_account("Phishing")),
        ],
    },
}

# =============================
# UI
# =============================
st.set_page_config(page_title="Cybersecurity Playbook Simulator", layout="wide")
st.title("Cybersecurity Playbook Simulator")
st.caption("Policy-bounded AI Agent with per-session isolation (Neon Postgres).")
st.info(f"Anonymous session: `{NS}` • "
        f"[Open this session in a new tab](?ns={NS}&embed=true)", icon="👤")

with st.expander("How to use this simulator", expanded=False):
    st.markdown("""
**Welcome!** This simulator lets you explore how **security policies** can allow or block automated responses during cyber incidents.

**Quick steps**
1. Choose a scenario below.  
2. In the sidebar, toggle **one policy at a time** (then **Save policies**).  
3. Click **Execute** to run the agent.  
4. Review the **Execution trace** and **Audit log** to see what was allowed/denied—and why.

**Policies**
- Allow log access — query security/system logs  
- Allow network controls — block IP, etc.  
- Allow account management — disable a user  
- Allow endpoint isolation — isolate a host  
- Require human approval — blocks all tools (simulates approval flow)  
- Enable audit logging — record ALLOW/DENY + reason
""")

# Initialize DB (creates tables on first run)
init_db_pg()

# --- Scenario select (reset THIS session's policies on change)
def on_scenario_change():
    reset_all_policies_to_disabled_ns()
    st.session_state["trace"] = []
    try:
        st.toast("Policies reset for the new scenario.", icon="✅")
    except Exception:
        pass

st.markdown("#### 1) Choose an Incident Scenario")
scenario_key = st.selectbox(
    "Select an incident scenario from the menu below",
    options=list(SCENARIOS.keys()),
    format_func=lambda k: SCENARIOS[k]["title"],
    key="scenario_select",
    on_change=on_scenario_change,
)
scenario = SCENARIOS[scenario_key]
st.markdown(f"**Description:** {scenario['description']}")

# --- Sidebar policies (namespaced to NS)
with st.sidebar:
    st.header("Policies (applies to your session only)")
    pol = get_policies_ns()

    allow_log = st.checkbox(
        "Allow log access",
        value=(pol.get("allow_log_access", "false").lower() == "true"),
        help="If disabled, the agent cannot query system/security logs.",
        key="allow_log_access_cb",
    )
    allow_net = st.checkbox(
        "Allow network controls (block IP)",
        value=(pol.get("allow_network_controls", "false").lower() == "true"),
        help="If disabled, IP blocks and similar network actions are denied.",
        key="allow_network_controls_cb",
    )
    allow_acct = st.checkbox(
        "Allow account management (disable user)",
        value=(pol.get("allow_account_management", "false").lower() == "true"),
        help="If disabled, actions like disabling a user account are denied.",
        key="allow_account_management_cb",
    )
    allow_iso = st.checkbox(
        "Allow endpoint isolation",
        value=(pol.get("allow_endpoint_isolation", "false").lower() == "true"),
        help="If disabled, isolating a host from the network is denied.",
        key="allow_endpoint_isolation_cb",
    )
    require = st.checkbox(
        "Require human approval (blocks tools)",
        value=(pol.get("require_human_approval", "false").lower() == "true"),
        help="When enabled, all tool actions are denied to simulate an approval workflow.",
        key="require_human_approval_cb",
    )
    audit = st.checkbox(
        "Enable audit logging",
        value=(pol.get("audit_logging", "true").lower() == "true"),
        help="When enabled, every attempted action is recorded with allow/deny + reason.",
        key="audit_logging_cb",
    )

    if st.button("Save policies"):
        set_policy_ns("allow_log_access", "true" if allow_log else "false")
        set_policy_ns("allow_network_controls", "true" if allow_net else "false")
        set_policy_ns("allow_account_management", "true" if allow_acct else "false")
        set_policy_ns("allow_endpoint_isolation", "true" if allow_iso else "false")
        set_policy_ns("require_human_approval", "true" if require else "false")
        set_policy_ns("audit_logging", "true" if audit else "false")
        st.success("Policies saved.", icon="✅")

    st.markdown("---")
    st.subheader("Audit Log")
    if st.button("Clear my audit log"):
        clear_audit_ns()
        st.info("Your audit log was cleared (only your session).")

# --- Run simulator
st.markdown("### 2) Run the Simulator")
if st.button("Execute", type="primary"):
    st.session_state.trace = []
    for action_code, step_desc, fn in scenario["playbook"]:
        st.session_state.trace.append(f"STEP • {step_desc} [{action_code}]")
        result = fn()
        st.session_state.trace.append(f"→ {result}")
    st.session_state.trace.append("DONE")

# --- Output panes
st.markdown("### Execution trace")
if "trace" in st.session_state and st.session_state.trace:
    for line in st.session_state.trace:
        st.code(line)

st.markdown("---")
st.markdown("### Audit log")
rows = read_audit_ns(limit=100)
if rows:
    for ts, sc, action, allowed, params, reason in rows:
        status = "ALLOW" if allowed else "DENY"
        st.write(f"- `{ts}` — **{sc}** — {action} → **{status}** — {params or ''} {('— ' + reason) if reason else ''}")
else:
    st.write("No audit entries yet.")
