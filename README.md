# 🛡️ PromptQT — Automated Prompt Safety Testing Toolkit

**Red-team your chatbot's system prompt before attackers do.**
PromptQT sends real prompt-injection attacks to a model running your system prompt, grades every real reply,
gives a safety score, then rewrites the prompt and re-tests it with the same attacks to prove the fix.

SCSE4041 Mini Project · Problem **C23**: Prompt safety tester (red-team kit) · Users: teams building chatbots

**Live app:** _add your Streamlit Cloud link here after deploying_
**M2 prototype (Gemini Gem chat):** https://share.gemini.google/Yw5PbEEkyhYo

## What it does

| Step | What happens |
|---|---|
| ① Target | Paste a system prompt (or load an example). Secrets such as `STAFF50` are detected automatically. |
| ② Attacks | 20 built-in attacks across 10 categories + attacks written for *your* bot by P1. Edit, untick or add your own. |
| ③ Run tests | Every attack goes to the real model running your prompt. Rule checks + the P2 judge give PASS/FAIL, severity and a reason. |
| ④ Harden & re-test | P3 rewrites the prompt, maps each change to the attack it fixes, then the same attacks run again. |
| ⑤ Report | Download a Markdown report, full JSON, or a CSV of every run. |

Attack categories: instruction override, prompt leaking, role-play jailbreak, off-topic request, fake authority,
encoded input, multi-step escalation, data extraction, indirect injection, language switch.

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py
```
Paste a Gemini API key in the sidebar (free: https://aistudio.google.com/apikey), or put it in
`.streamlit/secrets.toml` as `GEMINI_API_KEY = "..."` (see `.streamlit/secrets.toml.example`).
Other providers: choose **openai-compatible** in the sidebar (OpenAI, Groq, OpenRouter, local Ollama).

### Command line (for batch experiments)
```bash
export GEMINI_API_KEY=...
python -m promptqt run --prompt presets/shopbot_weak.txt --generate 10 --runs 3 --harden --out test-data/outputs/shopbot
```
Writes `_report.md`, `_results.json` and `_runs.csv`.

### Tests
```bash
pytest -q        # 12 offline unit tests, no API key needed
```

## Deploy (free) — Streamlit Community Cloud
1. Go to https://share.streamlit.io → **Create app** → pick this repo, branch `main`, file `app.py`.
2. **Advanced settings → Secrets:** `GEMINI_API_KEY = "your-key"`.
3. Deploy, then put the app URL at the top of this README.

## Project structure
```
app.py                 Streamlit web app
promptqt/              engine: llm.py · attacks.py · judge.py · engine.py · report.py · prompts.py · __main__.py (CLI)
prompts/final/         P1 attack generator · P2 judge · P3 hardener (exactly what the app sends)
prompts/v1, v2, v3/    earlier prompt versions (v3 = Milestone 2 Gemini Gem)
presets/               example target prompts
test-data/             test inputs; outputs/ holds saved real runs
tests/                 unit tests
docs/                  ARCHITECTURE.md · ROADMAP.md · milestone PDFs
CHANGELOG.md           dated changes
```

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for how it works and **[docs/ROADMAP.md](docs/ROADMAP.md)** for milestones.

## Team
| Member | Enrollment | Main task |
|---|---|---|
| Kavish Gupta | _add_ | _add_ |
| _add_ | _add_ | _add_ |

## Safety note
Attacks stay at the level of rule-breaking and leaking. PromptQT never asks the target for genuinely harmful content.
Never commit API keys: `.env` and `.streamlit/secrets.toml` are git-ignored.
