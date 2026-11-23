#!/usr/bin/env python3
"""Validate SKILL.md frontmatter against the Agent Skills specification.

Checks the required `name` and `description` fields for every SKILL.md under
Skills/ using the constraints from https://agentskills.io/specification:
`name` is 1-64 chars of lowercase letters, digits and hyphens, must not start
or end with a hyphen, must not contain consecutive hyphens, and must match the
skill's directory name; `description` is 1-1024 chars.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "Skills"

DESCRIPTION_MAX = 1024
NAME_MAX = 64
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)


def parse_frontmatter(text: str) -> dict[str, str]:
    """Return the frontmatter as a mapping of top-level keys to strings.

    Only string fields are needed here, so folded (`>`) and literal (`|`)
    block scalars are joined into one line; quoted and plain scalars are
    unquoted.
    """
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}

    fields: dict[str, str] = {}
    key: str | None = None
    block: list[str] = []
    folded = False

    def flush() -> None:
        if key is None:
            return
        value = "\n".join(block).strip()
        if folded:
            value = " ".join(part.strip() for part in block if part.strip())
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        fields[key] = value

    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        if ":" in line and not line.startswith((" ", "\t")):
            flush()
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            folded = value in (">", "|-", "|", ">-")
            block = [] if folded else [value]
        elif key is not None:
            block.append(line)
    flush()
    return fields


def check_skill(skill_md: Path) -> list[str]:
    problems: list[str] = []
    rel = skill_md.relative_to(ROOT)
    fields = parse_frontmatter(skill_md.read_text(encoding="utf-8"))

    if not fields:
        return [f"{rel}: missing YAML frontmatter"]

    name = fields.get("name", "")
    if not name:
        problems.append(f"{rel}: missing required `name`")
    else:
        if len(name) > NAME_MAX:
            problems.append(f"{rel}: name is {len(name)} chars (max {NAME_MAX})")
        if not NAME_RE.match(name):
            problems.append(
                f"{rel}: name {name!r} must be lowercase letters, digits and single hyphens"
            )
        if name != skill_md.parent.name:
            problems.append(
                f"{rel}: name {name!r} does not match directory {skill_md.parent.name!r}"
            )

    description = fields.get("description", "")
    if not description:
        problems.append(f"{rel}: missing required `description`")
    elif len(description) > DESCRIPTION_MAX:
        problems.append(
            f"{rel}: description is {len(description)} chars "
            f"({len(description) - DESCRIPTION_MAX} over the {DESCRIPTION_MAX} limit)"
        )
    return problems


def main() -> int:
    skill_files = sorted(SKILLS_DIR.rglob("SKILL.md"))
    if not skill_files:
        print(f"No SKILL.md files found under {SKILLS_DIR}")
        return 1

    problems: list[str] = []
    for skill_md in skill_files:
        problems.extend(check_skill(skill_md))

    for problem in problems:
        print(problem)

    if problems:
        print(f"\n{len(problems)} problem(s) in {len(skill_files)} skills")
        return 1

    print(f"OK: {len(skill_files)} skills conform to the Agent Skills spec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
