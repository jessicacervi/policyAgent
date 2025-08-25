import os
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime
import streamlit as st

# -----------------------------
# Choose a writable DB path
#   - On Streamlit Cloud: /mount/src (repo) is read-only; /mount/data is writable.
#   - Fallback to OS temp dir if /mount/data doesn't exist.
# -----------------------------
def _default_db_path() -> str:
    data_dir = Path("/mount/data")
    if data_dir.exists() and os.access(data_dir, os.W_OK):
        return str(data_dir / "policy_agent.db")
    # local/dev: current working dir is usually writable; if not, use temp dir
    cwd = Path.cwd()
    try:
        test = cwd / ".writetest"
        test.write_text("ok")
        test.unlink(missing_ok=True)
        return str(cwd / "policy_agent.db")
    except Exception:
        return str(Path(tempfile.gettempdir()) / "policy_agent.db")

DB_PATH = _default_db_path()

# -----------------------------
# SQLite helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    return conn

def ensure_schema():
    with get_conn() as conn:
        # --- policies table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)
        # --- audit_log table (create minimal, we'll add columns as needed)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            action TEXT NOT NULL,
            allowed INTEGER NOT NULL
        )
        """)
        # Inspect columns
        cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
        # Add missing columns
        if "scenario" not in cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN scenario TEXT DEFAULT ''")
        if "params" not in cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN params TEXT DEFAULT ''")
        if "reason" not in cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN reason TEXT DEFAULT ''")
        conn.commit()

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    ensure_schema()
    # Seed default policies if empty
    with get_conn() as conn:
        (n,) = conn.execute("SELECT COUNT(*) FROM policies").fetchone()
        if n == 0:
            defaults = {
                "allow_log_access": "true",
                "allow_account_management": "false",
                "allow_endpoint_isolation": "false",
                "require_human_approval": "false",
                "audit_logging": "true",
            }
            for k, v in defaults.items():
                conn.execute("INSERT INTO policies(key,value) VALUES(?,?)", (k, v))
        conn.commit()

def get_policies() -> dict[str, str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM policies").fetchall()
    return {k: v for k, v in rows}

def set_policy(key: str, value: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO policies(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()

def log_decision(scenario: str, action: str, allowed: bool, params: str = "", reason: str = ""):
    # Non-fatal audit: failure here should not crash the playbook
    try:
        pol = get_policies()
        if pol.get("audit_logging", "true").lower() != "true":
            return
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log(ts, scenario, action, allowed, params, reason) VALUES(?,?,?,?,?,?)",
                (datetime.utcnow().isoformat(timespec="seconds")+"Z", scenario, action, 1 if allowed else 0, params, reason),
            )
            conn.commit()
    except Exception as e:
        # Surface a gentle warning in the UI once per run
        st.session_state["_audit_warn"] = f"Audit log write failed: {e}"

def read_audit(limit: int = 100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ts, scenario, action, allowed, params, reason FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return rows

def clear_audit():
    with get_conn() as conn:
        conn.execute("DELETE FROM audit_log")
        conn.commit()

# -----------------------------
# Policy enforcement
# -----------------------------
def require_approval() -> bool:
    pol = get_policies()
    return pol.get("require_human_approval","false").lower() == "true"

def check_policy(action: str) -> tuple[bool, str]:
    if require_approval():
        return False, "Blocked: require_human_approval=true"
    pol = get_policies()
    if action == "logs.search":
        ok = pol.get("allow_log_access","true").lower() == "true"
        return ok, "Allowed by allow_log_access" if ok else "Blocked by allow_log_access=false"
    if action == "network.block_ip":
        ok = pol.get("allow_network_controls","false").lower() == "true"
        return ok, "Allowed by allow_network_controls" if ok else "Blocked by allow_network_controls=false"
    if action == "account.disable":
        ok = pol.get("allow_account_management","false").lower() == "true"
        return ok, "Allowed by allow_account_management" if ok else "Blocked by allow_account_management=false"
    if action == "endpoint.isolate":
        ok = pol.get("allow_endpoint_isolation","false").lower() == "true"
        return ok, "Allowed by allow_endpoint_isolation" if ok else "Blocked by allow_endpoint_isolation=false"
    return False, "Unknown action"

# -----------------------------
# Tools (simulated)
# -----------------------------
def tool_logs_search(keyword: str, scenario_name: str) -> str:
    ok, why = check_policy("logs.search")
    log_decision(scenario_name, "logs.search", ok, params=f"keyword={keyword}", reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return f"Found 3 log entries containing '{keyword}'. (simulated)"

def tool_block_ip(ip: str, scenario_name: str) -> str:
    ok, why = check_policy("network.block_ip")
    log_decision(scenario_name, "network.block_ip", ok, params=f"ip={ip}", reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return f"✅ Blocked IP {ip} at firewall. (simulated)"

def tool_disable_account(user: str, scenario_name: str) -> str:
    ok, why = check_policy("account.disable")
    log_decision(scenario_name, "account.disable", ok, params=f"user={user}", reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return f"✅ Disabled account {user} in IdP. (simulated)"

def tool_isolate_endpoint(host: str, scenario_name: str) -> str:
    ok, why = check_policy("endpoint.isolate")
    log_decision(scenario_name, "endpoint.isolate", ok, params=f"host={host}", reason=why)
    if not ok:
        return f"❌ Denied — {why}"
    return f"✅ Isolated endpoint {host} from network. (simulated)"

# -----------------------------
# Scenarios
# -----------------------------
SCENARIOS = {
    "brute_force": {
        "title": "Brute-force login from foreign IP",
        "description": "Multiple failed login attempts detected for a user account.",
        "context": {"user": "jessica.c", "ip": "185.23.91.10", "keyword": "auth_fail jessica.c"},
        "playbook": [
            ("logs.search", "Search logs", lambda ctx: tool_logs_search(ctx["keyword"], "Brute-force")),
            ("network.block_ip", "Block offending IP", lambda ctx: tool_block_ip(ctx["ip"], "Brute-force")),
            ("account.disable", "Disable account", lambda ctx: tool_disable_account(ctx["user"], "Brute-force")),
        ],
    },
    "malware_endpoint": {
        "title": "Malware detected on endpoint",
        "description": "EDR flagged malware on workstation; lateral movement suspected.",
        "context": {"host": "DESK-001", "keyword": "malware DESK-001"},
        "playbook": [
            ("endpoint.isolate", "Isolate endpoint", lambda ctx: tool_isolate_endpoint(ctx["host"], "Malware")),
            ("logs.search", "Search logs for IOCs", lambda ctx: tool_logs_search(ctx["keyword"], "Malware")),
        ],
    },
    "phishing": {
        "title": "Phishing reported by employee",
        "description": "User reported a suspicious email with a credential-harvesting link.",
        "context": {"user": "alex.t", "keyword": "email phishing alex.t"},
        "playbook": [
            ("logs.search", "Search mail logs", lambda ctx: tool_logs_search(ctx["keyword"], "Phishing")),
            ("account.disable", "Disable account", lambda ctx: tool_disable_account(ctx["user"], "Phishing")),
        ],
    },
}

# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="Cybersecurity Playbook Simulator", layout="wide")
st.title("Cybersecurity Playbook Simulator")
st.caption("Policy-bounded AI Agent simulator with audit logs.")
init_db()

with st.sidebar:
    st.header("Policies Available")
    pol = get_policies()
    allow_log = st.checkbox("Allow log access", value=(pol.get("allow_log_access","true").lower()=="true"))
    allow_net = st.checkbox("Allow network controls", value=(pol.get("allow_network_controls","false").lower()=="true"))
    allow_acct = st.checkbox("Allow account management", value=(pol.get("allow_account_management","false").lower()=="true"))
    allow_iso = st.checkbox("Allow endpoint isolation", value=(pol.get("allow_endpoint_isolation","false").lower()=="true"))
    require = st.checkbox("Require human approval", value=(pol.get("require_human_approval","false").lower()=="true"))
    audit = st.checkbox("Enable audit logging", value=(pol.get("audit_logging","true").lower()=="true"))

    if st.button("Save policies"):
        set_policy("allow_log_access", "true" if allow_log else "false")
        set_policy("allow_network_controls", "true" if allow_net else "false")
        set_policy("allow_account_management", "true" if allow_acct else "false")
        set_policy("allow_endpoint_isolation", "true" if allow_iso else "false")
        set_policy("require_human_approval", "true" if require else "false")
        set_policy("audit_logging", "true" if audit else "false")
        st.success(f"Policies saved. DB @ {DB_PATH}", icon="✅")

    st.markdown("---")
    st.subheader("Audit Log")
    if st.button("Clear audit log"):
        clear_audit()
        st.info("Audit log cleared.")

st.markdown("### 1) Choose a scenario")
scenario_key = st.selectbox(
    "Incident scenario",
    options=list(SCENARIOS.keys()),
    format_func=lambda k: SCENARIOS[k]["title"],
)
scenario = SCENARIOS[scenario_key]

st.markdown(f"**Description:** {scenario['description']}")
st.write("**Context:**")
for k, v in scenario["context"].items():
    st.write(f"- **{k}**: `{v}`")

st.markdown("### 2) Run the playbook")
if st.button("🚀 Execute playbook", type="primary"):
    st.session_state.trace = []
    ctx = scenario["context"]
    st.session_state.trace.append(f"PLAN: {len(scenario['playbook'])} steps for {scenario['title']}")
    for action_code, step_desc, fn in scenario["playbook"]:
        st.session_state.trace.append(f"STEP • {step_desc} [{action_code}]")
        result = fn(ctx)
        st.session_state.trace.append(f"→ {result}")
    if "_audit_warn" in st.session_state:
        st.warning(st.session_state.pop("_audit_warn"))
    st.session_state.trace.append("DONE")

st.markdown("### ✅ Execution trace")
if "trace" in st.session_state and st.session_state.trace:
    for line in st.session_state.trace:
        st.code(line)

st.markdown("---")
st.markdown("### 🧾 Recent audit log")
rows = read_audit(limit=100)
if rows:
    for ts, sc, action, allowed, params, reason in rows:
        status = "ALLOW" if allowed else "DENY"
        st.write(f"- `{ts}` — **{sc}** — {action} → **{status}** — {params or ''} {('— '+reason) if reason else ''}")
else:
    st.write("No audit entries yet.")


