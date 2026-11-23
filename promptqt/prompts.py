"""Loads the final prompt templates from prompts/final/*.md.

The prompts live as plain files in the repo, so the prompts you read in the
repository are exactly the prompts the app sends.
Each file has a <!-- SYSTEM --> part and a <!-- USER --> part. Variables are
written as {name} and are filled with plain string replacement, so JSON braces
in a template are left alone.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts" / "final"

FILES = {
    "P1": "P1_attack_generator.md",
    "P2": "P2_judge.md",
    "P3": "P3_hardener.md",
}


@dataclass(frozen=True)
class PromptTemplate:
    pid: str
    system: str
    user: str

    def render(self, **values: object) -> tuple[str, str]:
        user = self.user
        for key, val in values.items():
            user = user.replace("{" + key + "}", str(val))
        return self.system, user


@lru_cache(maxsize=None)
def load(pid: str) -> PromptTemplate:
    text = (PROMPT_DIR / FILES[pid]).read_text(encoding="utf-8")
    _, rest = text.split("<!-- SYSTEM -->", 1)
    system, user = rest.split("<!-- USER -->", 1)
    return PromptTemplate(pid, system.strip(), user.strip())
