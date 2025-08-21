import ast
import operator as op
import sqlite3
from datetime import datetime
import streamlit as st

DB_PATH = "policy_agent.db"

# -----------------------------
# SQLite helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            action TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            reason TEXT
        )
        """)
        # Seed defaults if empty
        cur = conn.execute("SELECT COUNT(*) FROM policies")
        (n,) = cur.fetchone()
        if n == 0:
            defaults = {
                "allow_calculator": "true",
                "allow_memory_search": "true",
                "require_human_approval": "false"
            }
            for k, v in defaults.items():
                conn.execute(
                    "INSERT INTO policies(key,value) VALUES(?,?)", (k, v)
                )
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

def log_decision(action: str, allowed: bool, reason: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log(ts, action, allowed, reason) VALUES(?,?,?,?)",
            (
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
                action,
                1 if allowed else 0,
                reason,
            ),
        )
        conn.commit()

def read_audit(limit: int = 200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ts, action, allowed, reason FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return rows

# -----------------------------
# Safe calculator (no eval)
# -----------------------------
_ALLOWED_OPS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.Pow: op.pow,
    ast.USub: op.neg,
    ast.Mod: op.mod,
}

def _safe_eval(node):
    if isinstance(node, ast.Num):  # type: ignore[attr-defined]
        return node.n
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](
            _safe_eval(node.left), _safe_eval(node.right)
        )
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("Unsupported expression")

def safe_calculate(expr: str):
    node = ast.parse(expr, mode="eval").body  # type: ignore[arg-type]
    return _safe_eval(node)

# -----------------------------
# Agent with policy enforcement
# -----------------------------
class PolicyBoundAgent:
    def __init__(self, memory: list[str] | None = None, max_steps: int = 4):
        self.memory = memory if memory is not None else []
        self.max_steps = max_steps
        self.trace: list[str] = []
        self.policies = get_policies()

    def refresh_policies(self):
        self.policies = get_policies()

    def log(self, msg: str):
        self.trace.append(msg)

    def check_policy(self, action: str) -> tuple[bool, str]:
        require_approval = (
            self.policies.get("require_human_approval", "false").lower() == "true"
        )
        if require_approval:
            return False, "Blocked: require_human_approval=true"

        if action == "calculator":
            allowed = (
                self.policies.get("allow_calculator", "true").lower() == "true"
            )
            return allowed, (
                "Allowed by allow_calculator"
                if allowed
                else "Blocked by allow_calculator=false"
            )
        if action == "memory.search":
            allowed = (
                self.policies.get("allow_memory_search", "true").lower() == "true"
            )
            return allowed, (
                "Allowed by allow_memory_search"
                if allowed
                else "Blocked by allow_memory_search=false"
            )
        return False, "Unknown action"

    def tool_calculator(self, text: str):
        ok, why = self.check_policy("calculator")
        log_decision("tool.calculator", ok, why)
        self.log(f"POLICY → calculator: {ok} ({why})")
        if not ok:
            return "❌ Denied by policy."
        try:
            result = safe_calculate(text)
            self.log(f"TOOL(calculator) → {result}")
            return str(result)
        except Exception as e:
            self.log(f"TOOL(calculator) ERROR → {e}")
            return f"Error: {e}"

    def tool_memory_search(self, query: str):
        ok, why = self.check_policy("memory.search")
        log_decision("tool.memory.search", ok, why)
        self.log(f"POLICY → memory.search: {ok} ({why})")
        if not ok:
            return []
        hits = [m for m in self.memory if query.lower() in m.lower()]
        self.log(f"TOOL(memory.search) → {hits[:3]}")
        return hits

    def act(self, goal: str, context: str = "") -> str:
        self.trace.clear()
        self.refresh_policies()
        goal_l = goal.strip().lower()
        plan = []

        if any(ch.isdigit() for ch in goal_l) and any(ch in "+-*/^%" for ch in goal_l):
            plan = ["Try calculator", "Summarize"]
        else:
            plan = ["Search memory", "Draft answer"]

        self.log(f"PLAN: {plan}")
        answer = ""

        for _ in range(self.max_steps):
            if not plan:
                break
            step = plan.pop(0).lower()
            if "calculator" in step:
                answer = self.tool_calculator(goal)
                continue
            if "search memory" in step:
                _ = self.tool_memory_search(goal)
                continue
            if "summarize" in step or "draft" in step:
                if answer:
                    answer = f"The result is: {answer}"
                else:
                    notes = (
                        "; ".join(self.memory[-3:]) if self.memory else "no prior notes"
                    )
                    answer = (
                        f"Answer based on goal & context.\n"
                        f"- Goal: {goal}\n- Context: {context or 'n/a'}\n- Memory: {notes}"
                    )
                break

        log_decision("agent.finish", True, "Completed reasoning loop")
        self.log("DONE")
        return answer

# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="Policy-Bounded Tiny Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ Policy-Bounded Tiny Agent")
st.caption("Policies & audit logs are stored in a local SQLite database.")

init_db()

with st.sidebar:
    st.header("Policy Store (SQLite)")
    policies = get_policies()

    allow_calc = st.checkbox(
        "Allow calculator",
        value=(policies.get("allow_calculator", "true").lower() == "true"),
        key="pol_calc",
    )
    allow_mem = st.checkbox(
        "Allow memory search",
        value=(policies.get("allow_memory_search", "true").lower() == "true"),
        key="pol_mem",
    )
    require_approval = st.checkbox(
        "Require human approval (blocks tools)",
        value=(policies.get("require_human_approval", "false").lower() == "true"),
        key="pol_approval",
    )

    if st.button("💾 Save policies", use_container_width=True, key="save_policies"):
        set_policy("allow_calculator", "true" if allow_calc else "false")
        set_policy("allow_memory_search", "true" if allow_mem else "false")
        set_policy("require_human_approval", "true" if require_approval else "false")
        st.success("Policies saved to SQLite.", icon="✅")

    st.markdown("---")
    st.subheader("Scratchpad Memory")
    if "memory" not in st.session_state:
        st.session_state.memory = []

    mem_item = st.text_input("Add note", key="mem_input")
    if st.button("➕ Add", key="mem_add", use_container_width=True) and mem_item:
        st.session_state.memory.append(mem_item)
        st.success("Added note.")

    if st.session_state.memory:
        st.write("**Notes:**")
        for i, note in enumerate(st.session_state.memory, start=1):
            st.write(f"{i}. {note}")
        if st.button("🗑️ Clear memory", key="mem_clear", use_container_width=True):
            st.session_state.memory = []
            st.info("Memory cleared.")

st.markdown("### 1) Define your objective")
goal = st.text_input(
    "What should the agent do?",
    placeholder="e.g., 12*(3+5) or 'Summarize my onboarding notes'",
)

st.markdown("### 2) Optional context")
context = st.text_area(
    "Any extra info?", placeholder="Paste background details or constraints here..."
)

col_run, col_steps = st.columns([1, 1])
with col_steps:
    max_steps = st.slider("Max steps", 1, 8, 4, key="max_steps")

with col_run:
    run = st.button("🚀 Run agent", type="primary", use_container_width=True, key="run_agent")

if "agent" not in st.session_state:
    st.session_state.agent = PolicyBoundAgent(
        memory=st.session_state.get("memory", []), max_steps=max_steps
    )

st.session_state.agent.memory = st.session_state.get("memory", [])
st.session_state.agent.max_steps = max_steps

if run:
    if not goal.strip():
        st.warning("Please enter an objective first.")
    else:
        result = st.session_state.agent.act(goal, context)
        st.success("Agent finished.", icon="✅")
        st.markdown("### ✅ Result")
        st.write(result)

        with st.expander("🔎 Execution trace"):
            for line in st.session_state.agent.trace:
                st.code(line)

st.markdown("---")
st.markdown("### 🧾 Recent audit log (SQLite)")
rows = read_audit(limit=100)
if rows:
    for ts, action, allowed, reason in rows:
        status = "ALLOW" if allowed else "DENY"
        st.write(f"- `{ts}` — **{action}** → **{status}** — {reason or ''}")
else:
    st.write("No audit entries yet.")

st.caption("Tip: Toggle policies in the sidebar and re-run the agent to see enforcement in action.")


