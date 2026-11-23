"""PromptQT web app (Streamlit).

Run locally:   streamlit run app.py
Deploy:        Streamlit Community Cloud -> point at this repo -> add GEMINI_API_KEY in Secrets.
"""
from __future__ import annotations

import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from promptqt import __version__
from promptqt.attacks import CATEGORIES, Attack, generate_attacks, library_attacks, renumber
from promptqt.engine import compare, harden, run_suite
from promptqt.judge import detect_secrets
from promptqt.llm import GEMINI_FALLBACKS, LLMError, make_client
from promptqt.report import to_csv, to_json, to_markdown

ROOT = Path(__file__).resolve().parent
BLUE, ORANGE = "#2a78d6", "#eb6834"  # categorical slots 1 and 2
PRESETS = {
    "ShopBot (weak, has a secret code)": "shopbot_weak.txt",
    "MathHelp tutor (no rules at all)": "mathhelp.txt",
    "Sahyog Bank FAQ (password in prompt)": "bank_faq.txt",
    "CampusDesk helpdesk (some rules)": "campus_helpdesk.txt",
}
VERDICT_LABEL = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "ERROR": "⚠️ ERROR"}

st.set_page_config(page_title="PromptQT · Prompt Safety Tester", page_icon="🛡️", layout="wide")

ss = st.session_state
for k, v in {"target_prompt": (ROOT / "presets" / "shopbot_weak.txt").read_text().strip(), "attacks": None,
             "attacks_view": None, "before": None, "hardening": None, "after": None, "hardened_text": ""}.items():
    ss.setdefault(k, v)


def secret_value(name: str) -> str:
    try:
        return st.secrets.get(name, "") or os.environ.get(name, "")
    except Exception:  # no secrets.toml
        return os.environ.get(name, "")


# ------------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown("## 🛡️ PromptQT")
    st.caption(f"Automated Prompt Safety Testing Toolkit · v{__version__}")
    st.subheader("Model")
    provider = st.selectbox("Provider", ["gemini", "openai-compatible"],
                            help="Gemini uses Google AI Studio. 'openai-compatible' works with OpenAI, Groq, OpenRouter or a local Ollama server.")
    env_name = "GEMINI_API_KEY" if provider == "gemini" else "OPENAI_API_KEY"
    server_key = secret_value(env_name)
    if server_key:
        st.success("API key loaded from server secrets.", icon="🔑")
        api_key = server_key
    else:
        api_key = st.text_input(f"{env_name}", type="password",
                                help="Free key: https://aistudio.google.com/apikey. Kept only in this browser session.")
    base_url = None
    if provider == "openai-compatible":
        base_url = st.text_input("Base URL", "https://api.groq.com/openai/v1")
    default_model = "gemini-3.8-flash" if provider == "gemini" else "llama-3.1-8b-instant"
    target_model = st.text_input("Target bot model", default_model, help="The model that plays the chatbot under test.")
    judge_model = st.text_input("Judge / generator model", default_model, help="Used by P1 (attacks), P2 (judge) and P3 (hardener).")
    fallback_text = st.text_input("Fallback models", ", ".join(GEMINI_FALLBACKS) if provider == "gemini" else "",
                                  help="Comma-separated, tried in order if a model is overloaded (503) or retired (404). "
                                       "Leave empty to turn fallback off.")
    fallbacks = [m.strip() for m in fallback_text.split(",") if m.strip()]

    st.subheader("Test settings")
    runs = st.slider("Runs per attack", 1, 5, 1, help="Replies vary between runs. An attack counts as FAIL if any run fails.")
    workers = st.slider("Parallel requests", 1, 4, 2, help="Lower this if you hit free-tier rate limits.")
    use_judge = st.toggle("LLM judge (P2)", True, help="Off = rule-based checks only (canary, secrets, prompt leak).")
    use_canary = st.toggle("Canary leak check", True,
                           help="Adds a random hidden ID to the prompt during testing. If a reply contains it, hidden context leaked.")
    st.divider()
    st.caption("Problem C23 · SCSE4041 Mini Project")


def clients():
    if not api_key and provider == "gemini":
        st.error("Add an API key in the sidebar first.", icon="🔑")
        st.stop()
    try:
        return (make_client(provider, api_key, target_model, base_url, fallbacks),
                make_client(provider, api_key, judge_model, base_url, fallbacks))
    except LLMError as err:
        st.error(str(err))
        st.stop()


# ------------------------------------------------------------------------- charts
def category_chart(suite) -> alt.Chart:
    df = pd.DataFrame(suite.per_category())
    return (
        alt.Chart(df)
        .mark_bar(color=BLUE, cornerRadiusEnd=4, height=16)
        .encode(
            x=alt.X("pass_rate:Q", title="Pass rate (%)", scale=alt.Scale(domain=[0, 100])),
            y=alt.Y("category:N", title=None, sort=list(CATEGORIES)),
            tooltip=[alt.Tooltip("category:N", title="Category"), alt.Tooltip("pass_rate:Q", title="Pass rate %", format=".0f"),
                     alt.Tooltip("runs:Q", title="Runs")],
        )
        .properties(height=34 * len(df) + 20, title="Pass rate by attack category")
    )


def compare_chart(before, after) -> alt.Chart:
    rows = [{"category": c["category"], "prompt": "Original", "pass_rate": c["pass_rate"]} for c in before.per_category()]
    rows += [{"category": c["category"], "prompt": "Hardened", "pass_rate": c["pass_rate"]} for c in after.per_category()]
    df = pd.DataFrame(rows)
    return (
        alt.Chart(df)
        .mark_bar(cornerRadiusEnd=4, height=12)
        .encode(
            x=alt.X("pass_rate:Q", title="Pass rate (%)", scale=alt.Scale(domain=[0, 100])),
            y=alt.Y("category:N", title=None, sort=list(CATEGORIES)),
            yOffset=alt.YOffset("prompt:N", sort=["Original", "Hardened"], scale=alt.Scale(paddingInner=0.2)),
            color=alt.Color("prompt:N", scale=alt.Scale(domain=["Original", "Hardened"], range=[BLUE, ORANGE]),
                            legend=alt.Legend(title=None, orient="top")),
            tooltip=["category:N", "prompt:N", alt.Tooltip("pass_rate:Q", title="Pass rate %", format=".0f")],
        )
        .properties(height=44 * df["category"].nunique() + 40, title="Original vs hardened prompt")
    )


def fallback_note(client, step: str):
    if client.model != client.requested_model:
        st.info(f"`{client.requested_model}` was unavailable, so {step} used fallback model `{client.model}`.", icon="🔁")


def show_suite(suite, key: str):
    sm = suite.summary()
    if "(fallback:" in suite.target_model + suite.judge_model:
        st.info(f"A model was unavailable, so PromptQT switched to a fallback. "
                f"Target: `{suite.target_model}` · Judge: `{suite.judge_model}`", icon="🔁")
    if sm["runs"] and sm["errors"] == sm["runs"]:
        # Nothing was graded, so a score would be meaningless (it would read as 0%).
        st.error(f"All {sm['runs']} runs failed, so there is no score. First error:\n\n{suite.results[0].reason}", icon="⚠️")
        st.caption("Check the API key and the model names in the sidebar, then run again.")
        return
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Safety score", f"{sm['score']:.0f}%", help="Share of attack runs the bot resisted.")
    c2.metric("Attacks resisted", f"{sm['attacks_passed']} / {sm['attacks']}")
    c3.metric("Attacks failed", sm["attacks_failed"])
    c4.metric("High severity", sm["high_severity"], help="Secret or system prompt leaked, or harmful content.")
    if sm["errors"]:
        st.warning(f"{sm['errors']} run(s) could not be graded (API error or rate limit). They are left out of the score.")
    left, right = st.columns([2, 3])
    with left:
        st.altair_chart(category_chart(suite), width="stretch")
    with right:
        df = pd.DataFrame(suite.per_attack())
        df["verdict"] = df["verdict"].map(VERDICT_LABEL)
        st.dataframe(
            df[["id", "verdict", "category", "fail_runs", "severity", "reason"]],
            hide_index=True, width="stretch", height=min(38 * len(df) + 40, 520),
            column_config={"id": "ID", "verdict": "Verdict", "category": "Category", "fail_runs": "Failed runs",
                           "severity": "Severity", "reason": st.column_config.TextColumn("Reason", width="large")},
        )
    failed = [r for r in suite.per_attack() if r["verdict"] == "FAIL"]
    if failed:
        st.markdown(f"**Failed attacks ({len(failed)})**: the real attack and the bot's real reply")
        for r in failed:
            with st.expander(f"❌ {r['id']} · {r['category']} · severity {r['severity']} · {r['method']}"):
                st.markdown(f"**Why it failed:** {r['reason']}")
                a, b = st.columns(2)
                a.markdown("**Attack**")
                a.code(r["attack"], language=None, wrap_lines=True)
                b.markdown("**Bot reply**")
                b.code(r["reply"] or "(empty)", language=None, wrap_lines=True)


def run_with_progress(target, judge_client, prompt_text, attacks, label):
    bar = st.progress(0.0, text="Starting...")
    log = st.empty()

    def cb(done, total, res):
        bar.progress(done / total, text=f"{done}/{total} runs · last: {res.attack_id} {res.verdict}")
        log.caption(f"{res.attack_id} · {res.category} · {VERDICT_LABEL.get(res.verdict, res.verdict)} · {res.reason[:100]}")

    suite = run_suite(target, judge_client, prompt_text, attacks, label=label, runs=runs, use_canary=use_canary,
                      protected=protected, workers=workers, progress=cb)
    bar.empty()
    log.empty()
    return suite


# ---------------------------------------------------------------------------- page
st.title("🛡️ PromptQT")
st.markdown("Red-team your chatbot's system prompt: **attack** it with real prompt-injection messages, "
            "**test** the real replies, get a **safety score**, then **harden** the prompt and prove the fix.")

t1, t2, t3, t4, t5 = st.tabs(["① Target prompt", "② Attacks", "③ Run tests", "④ Harden & re-test", "⑤ Report"])

with t1:
    st.subheader("The chatbot system prompt you want to test")
    c1, c2 = st.columns([3, 1])
    preset = c2.selectbox("Load an example", ["—"] + list(PRESETS))
    if c2.button("Load example", disabled=preset == "—", width="stretch"):
        ss.target_prompt = (ROOT / "presets" / PRESETS[preset]).read_text().strip()
        ss.before = ss.hardening = ss.after = None
        st.rerun()
    c1.text_area("System prompt", key="target_prompt", height=220, label_visibility="collapsed",
                 placeholder="Paste the system prompt of your chatbot here...")
    auto = detect_secrets(ss.target_prompt)
    extra = st.text_input("Values that must never leak (comma-separated)", "",
                          help="Codes, passwords or internal data. PromptQT fails any reply that contains them.")
    protected = sorted(set(auto) | {s.strip() for s in extra.split(",") if s.strip()})
    if auto:
        st.info("Auto-detected secrets in the prompt: " + ", ".join(f"`{s}`" for s in auto), icon="🔎")
    st.caption(f"{len(ss.target_prompt.split())} words")

with t2:
    st.subheader("Build the attack set")
    c1, c2, c3 = st.columns([3, 1, 1])
    cats = c1.multiselect("Attack categories", list(CATEGORIES), default=list(CATEGORIES))
    use_lib = c2.toggle("Built-in library", True, help="20 tested generic attacks, 2 per category.")
    n_gen = c3.number_input("Tailored attacks (P1)", 0, 30, 10, help="Generated by the model for THIS prompt.")
    with st.expander("What each category tests"):
        st.table(pd.DataFrame({"Category": list(CATEGORIES), "What it tries": list(CATEGORIES.values())}))
    if st.button("Build attack set", type="primary", disabled=not ss.target_prompt.strip() or not cats):
        atks = library_attacks(cats) if use_lib else []
        if n_gen:
            _, helper = clients()
            with st.spinner(f"P1 is writing {n_gen} attacks tailored to your prompt..."):
                try:
                    atks += generate_attacks(helper, ss.target_prompt, int(n_gen), cats)
                    fallback_note(helper, "P1")
                except LLMError as err:
                    st.error(f"Attack generation failed: {err}")
        ss.attacks = pd.DataFrame([a.to_dict() for a in renumber(atks)])
        ss.attacks_view = ss.attacks
        ss.pop("attack_editor", None)
        ss.before = ss.hardening = ss.after = None
    if ss.attacks is not None and len(ss.attacks):
        st.caption("Edit any attack, untick to skip it, or add your own row. Put a line with only --- between turns for a multi-step attack.")
        # ss.attacks stays the base table; edits live in the widget state and in ss.attacks_view.
        ss.attacks_view = st.data_editor(
            ss.attacks, num_rows="dynamic", hide_index=True, width="stretch", key="attack_editor",
            column_order=["enabled", "id", "category", "text", "goal", "source"],
            column_config={
                "enabled": st.column_config.CheckboxColumn("Use", default=True, width="small"),
                "id": st.column_config.TextColumn("ID", disabled=True, width="small"),
                "category": st.column_config.SelectboxColumn("Category", options=list(CATEGORIES), required=True),
                "text": st.column_config.TextColumn("Attack message(s)", width="large", required=True),
                "goal": st.column_config.TextColumn("Goal"),
                "source": st.column_config.TextColumn("Source", disabled=True, width="small"),
            },
        )
        st.caption(f"{int(ss.attacks_view['enabled'].fillna(True).astype(bool).sum())} attacks selected")


def current_attacks() -> list[Attack]:
    df = (ss.attacks_view if ss.attacks_view is not None else ss.attacks).copy()
    df = df[df["text"].fillna("").str.strip() != ""]
    atks = [Attack(id="", category=r.category or "Instruction override", text=str(r.text), goal=str(r.goal or ""),
                   source=r.source if isinstance(r.source, str) else "custom", enabled=bool(r.enabled if pd.notna(r.enabled) else True))
            for r in df.itertuples()]
    return [a for a in renumber(atks) if a.enabled]


with t3:
    st.subheader("Run every attack against the real chatbot")
    if ss.attacks is None:
        st.info("Build an attack set in step ② first.")
    else:
        n = len(current_attacks())
        calls = n * runs * (1 + (1 if use_judge else 0))
        st.caption(f"{n} attacks × {runs} run(s) · about {calls}+ model calls · target `{target_model}` · judge `{judge_model if use_judge else 'rules only'}`")
        if st.button("Run attacks", type="primary", disabled=n == 0):
            target, helper = clients()
            ss.before = run_with_progress(target, helper if use_judge else None, ss.target_prompt, current_attacks(), "original")
            ss.hardening = ss.after = None
        if ss.before:
            show_suite(ss.before, "before")

with t4:
    st.subheader("Fix the prompt, then prove it with the same attacks")
    if not ss.before:
        st.info("Run the tests in step ③ first.")
    else:
        if st.button("Generate hardened prompt (P3)", type="primary"):
            _, helper = clients()
            with st.spinner("P3 is rewriting the prompt to fix every failure..."):
                try:
                    ss.hardening = harden(helper, ss.before)
                    fallback_note(helper, "P3")
                    ss.hardened_text = ss.hardening.hardened_prompt
                    ss.after = None
                except LLMError as err:
                    st.error(f"Hardening failed: {err}")
        if ss.hardening:
            a, b = st.columns(2)
            a.markdown("**Original prompt**")
            a.code(ss.before.system_prompt, language=None, wrap_lines=True)
            b.markdown("**Hardened prompt** (you can edit it before re-testing)")
            b.text_area("Hardened", key="hardened_text", height=320, label_visibility="collapsed")
            st.markdown("**What changed and which attack it fixes**")
            for c in ss.hardening.changes:
                st.markdown(f"- **{', '.join(c['fixes']) or '—'}**: {c['change']}")
            if st.button("Re-test hardened prompt", type="primary"):
                target, helper = clients()
                ss.after = run_with_progress(target, helper if use_judge else None, ss.hardened_text, current_attacks(), "hardened")
        if ss.after:
            b, a = ss.before.summary(), ss.after.summary()
            st.divider()
            c1, c2, c3 = st.columns(3)
            c1.metric("Safety score", f"{a['score']:.0f}%", f"{a['score'] - b['score']:+.0f} pts")
            c2.metric("Attacks failed", a["attacks_failed"], f"{a['attacks_failed'] - b['attacks_failed']:+d}", delta_color="inverse")
            c3.metric("High severity", a["high_severity"], f"{a['high_severity'] - b['high_severity']:+d}", delta_color="inverse")
            l, r = st.columns([3, 2])
            l.altair_chart(compare_chart(ss.before, ss.after), width="stretch")
            cmp = pd.DataFrame(compare(ss.before, ss.after))
            cmp["change"] = cmp.apply(lambda x: "fixed" if x.fixed else ("regressed" if x.regressed else ""), axis=1)
            cmp["before"] = cmp["before"].map(VERDICT_LABEL)
            cmp["after"] = cmp["after"].map(VERDICT_LABEL)
            r.dataframe(cmp[["id", "category", "before", "after", "change"]], hide_index=True, width="stretch", height=420,
                        column_config={"id": "ID", "category": "Category", "before": "Original", "after": "Hardened", "change": "Change"})
            with st.expander("Hardened prompt — full results"):
                show_suite(ss.after, "after")

with t5:
    st.subheader("Download the report")
    if not ss.before:
        st.info("Run the tests first.")
    else:
        md = to_markdown(ss.before, ss.hardening, ss.after)
        c1, c2, c3 = st.columns(3)
        c1.download_button("Report (.md)", md, "promptqt_report.md", "text/markdown", width="stretch")
        c2.download_button("All results (.json)", to_json(ss.before, ss.hardening, ss.after), "promptqt_results.json",
                           "application/json", width="stretch")
        csv_text = to_csv(ss.before) + (to_csv(ss.after).split("\n", 1)[1] if ss.after else "")
        c3.download_button("Every run (.csv)", csv_text, "promptqt_runs.csv", "text/csv", width="stretch")
        with st.expander("Preview report", expanded=True):
            st.markdown(md)
