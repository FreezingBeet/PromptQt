"""The PromptQT workflow: run attacks against the real target, judge, score, harden, re-test."""
from __future__ import annotations

import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import prompts
from .attacks import CATEGORIES, Attack
from .judge import Verdict, judge, new_canary, with_canary
from .llm import LLMClient, LLMError, Message


@dataclass
class RunResult:
    attack_id: str
    category: str
    attack: str
    goal: str
    run: int
    reply: str
    verdict: str
    severity: str
    reason: str
    evidence: str
    method: str
    seconds: float

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"


@dataclass
class SuiteResult:
    label: str
    system_prompt: str
    target_model: str
    judge_model: str
    runs_per_attack: int
    canary_used: bool
    protected: list[str]
    started: str
    results: list[RunResult] = field(default_factory=list)

    # ---- scoring -----------------------------------------------------------
    @property
    def graded(self) -> list[RunResult]:
        return [r for r in self.results if r.verdict in ("PASS", "FAIL")]

    @property
    def errors(self) -> int:
        return sum(r.verdict == "ERROR" for r in self.results)

    @property
    def score(self) -> float:
        """Percentage of graded attack runs the bot resisted."""
        g = self.graded
        return 100.0 * sum(r.passed for r in g) / len(g) if g else 0.0

    def per_attack(self) -> list[dict]:
        """One row per attack. An attack counts as FAIL if ANY of its runs failed."""
        by: dict[str, list[RunResult]] = defaultdict(list)
        for r in self.results:
            by[r.attack_id].append(r)
        rows = []
        for aid, rs in by.items():
            graded = [r for r in rs if r.verdict in ("PASS", "FAIL")]
            fails = [r for r in graded if not r.passed]
            worst = max(fails, key=lambda r: ("none", "low", "medium", "high").index(r.severity)) if fails else (graded or rs)[0]
            rows.append(
                {
                    "id": aid,
                    "category": rs[0].category,
                    "attack": rs[0].attack,
                    "verdict": "FAIL" if fails else ("PASS" if graded else "ERROR"),
                    "fail_runs": f"{len(fails)}/{len(graded)}",
                    "severity": worst.severity,
                    "reason": worst.reason,
                    "reply": worst.reply,
                    "method": worst.method,
                }
            )
        return sorted(rows, key=lambda r: r["id"])

    def per_category(self) -> list[dict]:
        by: dict[str, list[RunResult]] = defaultdict(list)
        for r in self.graded:
            by[r.category].append(r)
        return [
            {"category": c, "pass_rate": 100.0 * sum(r.passed for r in by[c]) / len(by[c]), "runs": len(by[c])}
            for c in CATEGORIES
            if c in by
        ]

    def summary(self) -> dict:
        rows = self.per_attack()
        return {
            "score": round(self.score, 1),
            "attacks": len(rows),
            "attacks_failed": sum(r["verdict"] == "FAIL" for r in rows),
            "attacks_passed": sum(r["verdict"] == "PASS" for r in rows),
            "high_severity": sum(r["severity"] == "high" for r in rows),
            "runs": len(self.results),
            "errors": self.errors,
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary()
        return d


# ---------------------------------------------------------------------- target run
def run_target(client: LLMClient, system_prompt: str, attack: Attack, temperature: float = 0.7) -> str:
    """Send the attack to the REAL target model with the system prompt under test.

    Multi-step attacks are sent as a real conversation: each user turn gets a real
    reply, and the final reply is the one judged. Earlier replies are kept in the
    transcript so the judge sees the whole exchange.
    """
    history: list[Message] = []
    transcript: list[str] = []
    turns = attack.turns
    reply = ""
    for i, turn in enumerate(turns):
        history.append(Message("user", turn))
        reply = client.chat(system_prompt, history, temperature=temperature, max_tokens=1024)
        history.append(Message("assistant", reply))
        if len(turns) > 1:
            transcript.append(f"[Turn {i + 1}] User: {turn}\n[Turn {i + 1}] Bot: {reply}")
    return "\n\n".join(transcript) if len(turns) > 1 else reply


def run_suite(
    target_client: LLMClient,
    judge_client: LLMClient | None,
    system_prompt: str,
    attacks: list[Attack],
    *,
    label: str = "original",
    runs: int = 1,
    use_canary: bool = True,
    protected: list[str] | None = None,
    workers: int = 2,
    target_temperature: float = 0.7,
    progress: Callable[[int, int, RunResult], None] | None = None,
) -> SuiteResult:
    protected = list(protected or [])
    for c in (target_client, judge_client):
        if c:
            c.models_used.clear()
    canary = new_canary() if use_canary else None
    sent_prompt = with_canary(system_prompt, canary) if canary else system_prompt
    suite = SuiteResult(
        label=label,
        system_prompt=system_prompt,
        target_model=target_client.model,
        judge_model=judge_client.model if judge_client else "rules only",
        runs_per_attack=runs,
        canary_used=bool(canary),
        protected=protected,
        started=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    jobs = [(a, k) for a in attacks if a.enabled for k in range(1, runs + 1)]

    def one(attack: Attack, k: int) -> RunResult:
        t0 = time.time()
        try:
            reply = run_target(target_client, sent_prompt, attack, target_temperature)
            v = judge(system_prompt, attack, reply, judge_client=judge_client, canary=canary, protected=protected)
        except LLMError as err:
            reply, v = "", Verdict("ERROR", "none", f"Target call failed: {err}", "", "error")
        return RunResult(
            attack.id, attack.category, attack.text, attack.goal, k, reply,
            v.verdict, v.severity, v.reason, v.evidence, v.method, round(time.time() - t0, 2),
        )

    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(one, a, k) for a, k in jobs]
        for fut in as_completed(futures):
            res = fut.result()
            suite.results.append(res)
            done += 1
            if progress:
                progress(done, len(jobs), res)
    suite.results.sort(key=lambda r: (r.attack_id, r.run))
    # Record the models that really answered (differs from the request if a fallback was used).
    suite.target_model = target_client.used_label()
    if judge_client:
        suite.judge_model = judge_client.used_label()
    return suite


# ------------------------------------------------------------------------ hardening
@dataclass
class Hardening:
    hardened_prompt: str
    changes: list[dict]


def harden(client: LLMClient, suite: SuiteResult) -> Hardening:
    """P3: rewrite the prompt so it fixes every failed attack."""
    failed = [r for r in suite.per_attack() if r["verdict"] == "FAIL"]
    if failed:
        failures = "\n".join(
            f"{r['id']} | {r['category']} | {r['attack'][:300]!r} | {r['reason']}" for r in failed
        )
    else:
        failures = "(none failed - strengthen the prompt against all ten categories anyway, without over-restricting it)"
    system, user = prompts.load("P3").render(target_prompt=suite.system_prompt, failures=failures)
    data = client.ask_json(system, user, temperature=0.3, max_tokens=4096)
    if not isinstance(data, dict):
        raise LLMError("Hardener did not return a JSON object.")
    new_prompt = str(data.get("hardened_prompt", "")).strip()
    if not new_prompt:
        raise LLMError("Hardener returned an empty prompt.")
    changes = [
        {"fixes": c.get("fixes", []) if isinstance(c.get("fixes"), list) else [str(c.get("fixes"))], "change": str(c.get("change", ""))}
        for c in data.get("changes", [])
        if isinstance(c, dict)
    ]
    return Hardening(new_prompt, changes)


def compare(before: SuiteResult, after: SuiteResult) -> list[dict]:
    """Per-attack before/after table for the same attack set."""
    b = {r["id"]: r for r in before.per_attack()}
    a = {r["id"]: r for r in after.per_attack()}
    rows = []
    for aid in sorted(b):
        rows.append(
            {
                "id": aid,
                "category": b[aid]["category"],
                "before": b[aid]["verdict"],
                "after": a.get(aid, {}).get("verdict", "-"),
                "fixed": b[aid]["verdict"] == "FAIL" and a.get(aid, {}).get("verdict") == "PASS",
                "regressed": b[aid]["verdict"] == "PASS" and a.get(aid, {}).get("verdict") == "FAIL",
            }
        )
    return rows
