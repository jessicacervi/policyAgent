import ast
import operator as op
import streamlit as st

# -----------------------------
# Safe calculator (no eval)
# -----------------------------
# Allowed operators
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
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("Unsupported expression")

def safe_calculate(expr: str):
    try:
        node = ast.parse(expr, mode="eval").body  # type: ignore[arg-type]
        return _safe_eval(node)
    except Exception as e:
        raise ValueError(f"Cannot calculate expression: {e}")


# -----------------------------
# "Agent" core (simple heuristic loop)
# -----------------------------
class TinyAgent:
    def __init__(self, memory: list[str] | None = None, max_steps: int = 4):
        self.memory = memory if memory is not None else []
        self.max_steps = max_steps
        self.trace: list[str] = []

    def log(self, msg: str):
        self.trace.append(msg)

    def tool_calculator(self, text: str):
        self.log(f"TOOL(calculator) ← {text}")
        try:
            result = safe_calculate(text)
            self.log(f"TOOL(calculator) → {result}")
            return str(result)
        except Exception as e:
            self.log(f"TOOL(calculator) ERROR → {e}")
            return f"Error: {e}"

    def tool_memory_search(self, query: str):
        self.log(f"TOOL(memory.search) ← {query}")
        hits = [m for m in self.memory if query.lower() in m.lower()]
        self.log(f"TOOL(memory.search) → {hits[:3]}")
        return hits

    def act(self, goal: str, context: str = "") -> str:
        """Very small reasoning loop: plan → try tools → draft answer."""
        self.trace.clear()
        plan = []
        goal_l = goal.strip().lower()

        # Step 0: quick plan
        if any(ch.isdigit() for ch in goal) and any(ch in "+-*/^%" for ch in goal):
            plan = ["Try calculator", "Summarize the result"]
        else:
            plan = ["Search memory", "Draft a helpful answer"]

        self.log(f"PLAN: {plan}")

        # Loop
        answer = ""
        for step in range(1, self.max_steps + 1):
            self.log(f"STEP {step}")

            if "calculator" in plan[0].lower():
                answer = self.tool_calculator(goal)
                plan.pop(0)
                continue

            if "search memory" in plan[0].lower():
                _ = self.tool_memory_search(goal)
                plan.pop(0)
                continue

            # Draft answer
            if "draft" in plan[0].lower() or not plan:
                if answer:
                    answer = f"The result is: {answer}"
                else:
                    # fallback draft using context + memory
                    notes = "; ".join(self.memory[-3:]) if self.memory else "no prior notes"
                    answer = f"Here’s a simple response based on the goal and context.\n\n- Goal: {goal}\n- Context: {context or 'n/a'}\n- Memory: {notes}"
                break

        self.log("DONE")
        return answer


# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="Tiny Policy-Free Agent (Starter)", page_icon="🤖", layout="wide")

st.title("🤖 Tiny Agent — Starter Template")
st.caption("A minimal, no-API agent you can extend with real tools later.")

with st.sidebar:
    st.header("Settings")
    max_steps = st.slider("Max steps", min_value=1, max_value=8, value=4, key="max_steps_slider")
    st.markdown("---")
    st.subheader("Scratchpad Memory")
    mem_item = st.text_input("Add memory note", key="mem_input")
    add = st.button("➕ Add to memory", use_container_width=True, key="add_mem_btn")

    if "memory" not in st.session_state:
        st.session_state.memory = []

    if add and mem_item:
        st.session_state.memory.append(mem_item)
        st.success("Added note to memory.", icon="✅")

    if st.session_state.memory:
        st.write("**Current memory notes:**")
        for i, note in enumerate(st.session_state.memory, start=1):
            st.write(f"{i}. {note}")
        if st.button("🗑️ Clear memory", use_container_width=True, key="clear_mem_btn"):
            st.session_state.memory = []
            st.info("Memory cleared.")

st.markdown("### 1) Define your objective")
goal = st.text_input("What should the agent do?", placeholder="e.g., 12*(3+5) or 'Summarize my notes about onboarding'")

st.markdown("### 2) Optional context")
context = st.text_area("Any extra info?", placeholder="Paste background details or constraints here...")

run = st.button("🚀 Run agent", type="primary", use_container_width=True, key="run_btn")

# Initialize agent once
if "agent" not in st.session_state:
    st.session_state.agent = TinyAgent(memory=st.session_state.get("memory", []), max_steps=max_steps)

# Keep agent settings in sync
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
st.markdown("**Next steps**: add real tools (e.g., web search, vector DB, code exec, email/calendar) and route actions through a policy layer if needed.")

