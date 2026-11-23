# Changelog

## 2026-11-23 — Model update
- Default Gemini model changed from `gemini-2.5-flash` (retired for new API keys, returns 404) to `gemini-3.8-flash`
  in the app, the CLI and `GeminiClient`.
- If every run fails (bad key, wrong model name), the app now shows the error instead of a misleading 0% safety score.
- Model fallback: if a model is overloaded (503, after one retry) or retired (404), PromptQT switches to the next model in
  the sidebar's **Fallback models** list (Gemini default: `gemini-3.6-flash, gemini-3.5-flash-lite`) and stays on it.
  Results and reports record the model that really answered, and the app shows a note when a fallback was used.
- 4 new unit tests for the fallback (16 total).

## 2026-11-23 — Milestone 3: full product (v1.0.0)
- New Streamlit web app (`app.py`) with 5 steps: target, attacks, run tests, harden & re-test, report.
- New engine package `promptqt/`: provider layer (Gemini + OpenAI-compatible), attack library and P1 generator,
  real target runs (multi-step attacks as real conversations), rule checks + P2 judge, P3 hardener, scoring, reports.
- Replies now come from a real model running the target prompt (M2 only simulated them).
- Rule-based checks added: canary ID, secret leak (auto-detected secrets), verbatim prompt leak.
- Runs per attack (1–5) with worst-case verdicts; before/after comparison with fixed/regressed attacks.
- Prompts split into P1 attack generator, P2 judge and P3 hardener as files in `prompts/final/`.
- CLI for batch experiments; Markdown/JSON/CSV export; 12 offline unit tests.
- Repo reorganised into prompts/v1–v3, presets/, test-data/, docs/, tests/.
- Added docs/ARCHITECTURE.md and docs/ROADMAP.md.

## 2026-11-22 — Milestone 2
- Built PromptQT Gem with /attack, /test, /harden (prompt v3).
- Added 12 test inputs (normal, edge, invalid).
- Added README, prompts folder structure, docs.

## Before 2026-11-22
- Prompt v2: added red-team role, 10 attack categories, table output.
- Prompt v1: first plain prompt.
- Milestone 1 submitted: problem C23.
