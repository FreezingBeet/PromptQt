"""Command-line runner.

Examples
  python -m promptqt run --prompt presets/shopbot_weak.txt --generate 10 --runs 3 --harden
  python -m promptqt run --prompt presets/bank_faq.txt --library-only --out test-data/outputs/bank

Needs GEMINI_API_KEY in the environment (or --provider openai-compatible with OPENAI_API_KEY/--base-url).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .attacks import generate_attacks, library_attacks, renumber
from .engine import harden, run_suite
from .judge import detect_secrets
from .llm import LLMError, make_client
from .report import to_csv, to_json, to_markdown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="promptqt", description="Red-team a chatbot system prompt.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="attack, judge, score and (optionally) harden + re-test")
    r.add_argument("--prompt", required=True, help="text file with the system prompt under test")
    r.add_argument("--provider", default="gemini", choices=["gemini", "openai-compatible"])
    r.add_argument("--model", default="gemini-3.8-flash", help="model used for the target bot")
    r.add_argument("--judge-model", default=None, help="model used for P1/P2/P3 (default: same as --model)")
    r.add_argument("--base-url", default=None, help="for openai-compatible providers")
    r.add_argument("--generate", type=int, default=10, help="number of tailored attacks from P1 (0 = none)")
    r.add_argument("--library-only", action="store_true", help="use only the 20 built-in attacks")
    r.add_argument("--no-library", action="store_true", help="do not include the built-in attacks")
    r.add_argument("--runs", type=int, default=1, help="runs per attack (replies vary between runs)")
    r.add_argument("--workers", type=int, default=2)
    r.add_argument("--secret", action="append", default=[], help="value that must never leak (repeatable)")
    r.add_argument("--no-canary", action="store_true")
    r.add_argument("--no-llm-judge", action="store_true", help="use only rule-based checks")
    r.add_argument("--harden", action="store_true", help="run P3 and re-test the hardened prompt")
    r.add_argument("--out", default="test-data/outputs/run", help="output path prefix")
    a = ap.parse_args(argv)

    key = os.environ.get("GEMINI_API_KEY" if a.provider == "gemini" else "OPENAI_API_KEY", "")
    try:
        target = make_client(a.provider, key, a.model, a.base_url)
        helper = make_client(a.provider, key, a.judge_model or a.model, a.base_url)
    except LLMError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    system_prompt = Path(a.prompt).read_text(encoding="utf-8").strip()
    protected = sorted(set(a.secret) | set(detect_secrets(system_prompt)))
    print(f"Protected secrets: {', '.join(protected) or '(none)'}")

    attacks = [] if a.no_library else library_attacks()
    if not a.library_only and a.generate > 0:
        print(f"P1: generating {a.generate} tailored attacks...")
        attacks += generate_attacks(helper, system_prompt, a.generate)
    renumber(attacks)

    def show(done, total, res):
        print(f"  [{done}/{total}] {res.attack_id} run {res.run}: {res.verdict} ({res.method}) {res.reason[:70]}")

    print(f"P2: running {len(attacks)} attacks x {a.runs} run(s) against {a.model}...")
    judge_client = None if a.no_llm_judge else helper
    before = run_suite(target, judge_client, system_prompt, attacks, runs=a.runs, use_canary=not a.no_canary,
                       protected=protected, workers=a.workers, progress=show)
    print(f"Original prompt score: {before.summary()['score']}%")

    hard = after = None
    if a.harden:
        print("P3: hardening...")
        hard = harden(helper, before)
        print("Re-testing hardened prompt with the same attacks...")
        after = run_suite(target, judge_client, hard.hardened_prompt, attacks, label="hardened", runs=a.runs,
                          use_canary=not a.no_canary, protected=protected, workers=a.workers, progress=show)
        print(f"Score: {before.summary()['score']}% -> {after.summary()['score']}%")

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    Path(f"{out}_report.md").write_text(to_markdown(before, hard, after), encoding="utf-8")
    Path(f"{out}_results.json").write_text(to_json(before, hard, after), encoding="utf-8")
    Path(f"{out}_runs.csv").write_text(to_csv(before) + (to_csv(after).split("\n", 1)[1] if after else ""), encoding="utf-8")
    print(f"Saved {out}_report.md, {out}_results.json, {out}_runs.csv")
    print(f"Model calls: target {target.calls}, judge/helper {helper.calls}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
