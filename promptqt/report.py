"""Exports: Markdown report, CSV of every run, and full JSON."""
from __future__ import annotations

import csv
import io
import json

from .engine import Hardening, SuiteResult, compare


def _cell(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    text = text if len(text) <= limit else text[: limit - 1] + "…"
    return text.replace("|", "\\|")


def to_csv(suite: SuiteResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["suite", "attack_id", "category", "run", "verdict", "severity", "method", "reason", "attack", "reply", "seconds"])
    for r in suite.results:
        w.writerow([suite.label, r.attack_id, r.category, r.run, r.verdict, r.severity, r.method, r.reason, r.attack, r.reply, r.seconds])
    return buf.getvalue()


def to_json(before: SuiteResult, hardening: Hardening | None = None, after: SuiteResult | None = None) -> str:
    data = {"original": before.to_dict()}
    if hardening:
        data["hardening"] = {"hardened_prompt": hardening.hardened_prompt, "changes": hardening.changes}
    if after:
        data["hardened"] = after.to_dict()
        data["comparison"] = compare(before, after)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _suite_md(s: SuiteResult) -> list[str]:
    sm = s.summary()
    out = [
        f"**Safety score: {sm['score']}%** — {sm['attacks_passed']} of {sm['attacks']} attacks resisted, "
        f"{sm['attacks_failed']} failed ({sm['high_severity']} high severity).",
        "",
        f"Target model: `{s.target_model}` · Judge: `{s.judge_model}` · Runs per attack: {s.runs_per_attack} · "
        f"Canary check: {'on' if s.canary_used else 'off'} · Errors: {sm['errors']}",
        "",
        "| ID | Category | Attack | Verdict | Failed runs | Severity | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in s.per_attack():
        out.append(
            f"| {r['id']} | {r['category']} | {_cell(r['attack'], 80)} | {r['verdict']} | {r['fail_runs']} | {r['severity']} | {_cell(r['reason'], 90)} |"
        )
    out += ["", "| Category | Pass rate | Runs |", "|---|---|---|"]
    for c in s.per_category():
        out.append(f"| {c['category']} | {c['pass_rate']:.0f}% | {c['runs']} |")
    return out


def to_markdown(before: SuiteResult, hardening: Hardening | None = None, after: SuiteResult | None = None) -> str:
    lines = [
        "# PromptQT Safety Report",
        "",
        f"Generated: {before.started} (UTC)",
        "",
        "## Prompt under test",
        "```",
        before.system_prompt,
        "```",
        "",
        "## Results — original prompt",
        *_suite_md(before),
    ]
    if hardening:
        lines += ["", "## Hardened prompt", "```", hardening.hardened_prompt, "```", "", "### Changes", ""]
        for c in hardening.changes:
            lines.append(f"- **Fixes {', '.join(c['fixes']) or '-'}:** {c['change']}")
    if after:
        b, a = before.summary(), after.summary()
        lines += [
            "",
            "## Results — hardened prompt (same attacks)",
            *_suite_md(after),
            "",
            "## Before vs after",
            "",
            f"Score: **{b['score']}% → {a['score']}%** · Failed attacks: {b['attacks_failed']} → {a['attacks_failed']}",
            "",
            "| ID | Category | Before | After | |",
            "|---|---|---|---|---|",
        ]
        for r in compare(before, after):
            note = "fixed" if r["fixed"] else ("regressed" if r["regressed"] else "")
            lines.append(f"| {r['id']} | {r['category']} | {r['before']} | {r['after']} | {note} |")
    lines += ["", "## Full replies (worst run per attack)", ""]
    for r in before.per_attack():
        lines += [f"### {r['id']} — {r['category']} — {r['verdict']}", "", "**Attack:**", "```", r["attack"], "```", "**Reply:**", "```", r["reply"], "```", ""]
    return "\n".join(lines)
