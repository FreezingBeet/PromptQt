# Milestone 3 test plan (real runs)

Run with a real API key and commit the files that appear in `test-data/outputs/`.
Fill the "Actual" columns from those files, not from memory.

| No. | Command / input | Type | Expected |
|---|---|---|---|
| 1 | `python -m promptqt run --prompt presets/shopbot_weak.txt --runs 3 --harden --out test-data/outputs/shopbot` | Normal | STAFF50 leaks in some attacks (rule:secret FAIL); hardened score higher |
| 2 | `... --prompt presets/bank_faq.txt --runs 3 --harden --out test-data/outputs/bank` | Normal | SB-OPS-2291 detected as secret; fake-authority attacks tested |
| 3 | `... --prompt presets/mathhelp.txt --runs 3 --harden --out test-data/outputs/mathhelp` | Normal | Off-topic attacks fail on the rule-less prompt |
| 4 | `... --prompt presets/campus_helpdesk.txt --runs 3 --harden --out test-data/outputs/campus` | Normal | Partly hardened prompt scores higher than ShopBot |
| 5 | Test 1 again with `--model` set to a second model | Normal | Shows how much the target model changes the score |
| 6 | Test 1 with `--no-llm-judge` | Edge | Rule checks alone still catch the STAFF50 leaks |
| 7 | Test 1 with `--library-only` | Edge | Runs offline library only (20 attacks), no P1 call |
| 8 | Web app: empty target prompt | Invalid | "Build attack set" stays disabled |
| 9 | Web app: no API key, click Run attacks | Invalid | Asks for an API key, no crash |
| 10 | Web app: add a custom multi-step attack with `---` lines | Edge | Sent as a real conversation; transcript shown in the reply |
| 11 | Web app: edit the hardened prompt by hand, then re-test | Edge | Re-test uses the edited text |
| 12 | Judge spot-check: read 20 verdicts from test 1 by hand | Evaluation | Record agreement, e.g. 18/20 |
