#!/usr/bin/env python3
"""Validate every SKILL.md in the library.

Guards against the class of defect where a skill file cannot be discovered by a
spec-compliant installer (``npx skills add``, Claude Skills) because its YAML
frontmatter is missing or malformed -- the file is then silently skipped and
never installed.

Checks performed:

1. Leading YAML frontmatter block exists.
2. ``name`` and ``description`` are both present and non-empty.
3. ``name`` matches its directory name (repo convention; also what the
   installer uses for the on-disk skill folder).
4. ``name`` matches ``^[a-z0-9]+(-[a-z0-9]+)*$`` and is <= 64 characters.
5. No two skills share a ``name``.
6. ``README.md`` advertises the real skill count (the ``skills-NN-`` badge).
7. ``claude-skills.json``, when present, lists every skill and no empty
   description.

Exits 0 when clean, 1 when any error is found. Over-long descriptions are
reported as warnings only -- they do not block installs.

Usage::

    python tools/validate_skills.py
    python tools/validate_skills.py --root path/to/repo
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\s*(\n|$)", re.DOTALL)
NAME_RE = re.compile(r"^name\s*:\s*(.+)$", re.MULTILINE)
DESCRIPTION_RE = re.compile(r"^description\s*:\s*(.*(?:\n(?![A-Za-z_][A-Za-z0-9_-]*\s*:).*)*)", re.MULTILINE)
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
README_BADGE_RE = re.compile(r"skills-(\d+)-\w+\.svg")

MAX_NAME_LEN = 64
RECOMMENDED_DESC_LEN = 1024  # Anthropic guidance; long descriptions still install.


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\\\", "\\")


def parse_frontmatter(text: str) -> dict[str, str]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}
    block = match.group(1)
    out: dict[str, str] = {}
    name = NAME_RE.search(block)
    if name:
        out["name"] = unquote(name.group(1))
    desc = DESCRIPTION_RE.search(block)
    if desc:
        raw = desc.group(1).strip()
        raw = raw.lstrip(">|").strip() if raw[:1] in ">|" else raw
        out["description"] = unquote(" ".join(raw.split()))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=None, help="repository root (default: parent of tools/)")
    args = parser.parse_args()

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    skills_dir = root / "Skills"
    if not skills_dir.is_dir():
        print(f"error: {skills_dir} not found", file=sys.stderr)
        return 1

    errors: list[str] = []
    warnings: list[str] = []
    seen: dict[str, str] = {}
    count = 0

    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        count += 1
        rel = skill_md.relative_to(root).as_posix()
        dir_name = skill_md.parent.name
        fm = parse_frontmatter(skill_md.read_text(encoding="utf-8"))

        if not fm:
            errors.append(f"{rel}: missing leading YAML frontmatter")
            continue

        name = fm.get("name", "")
        description = fm.get("description", "")

        if not name:
            errors.append(f"{rel}: frontmatter is missing a non-empty `name`")
        else:
            if name != dir_name:
                errors.append(f"{rel}: `name: {name}` does not match directory `{dir_name}`")
            if not SLUG_RE.match(name):
                errors.append(f"{rel}: `name: {name}` must be lowercase alphanumeric with single hyphens")
            if len(name) > MAX_NAME_LEN:
                errors.append(f"{rel}: `name` is {len(name)} chars (max {MAX_NAME_LEN})")
            if name in seen:
                errors.append(f"{rel}: duplicate `name: {name}` (also used by {seen[name]})")
            else:
                seen[name] = rel

        if not description:
            errors.append(f"{rel}: frontmatter is missing a non-empty `description`")
        elif len(description) > RECOMMENDED_DESC_LEN:
            warnings.append(f"{rel}: description is {len(description)} chars (recommended max {RECOMMENDED_DESC_LEN})")

    print(f"Scanned {count} SKILL.md files under {skills_dir.relative_to(root).as_posix()}/")

    readme = root / "README.md"
    if readme.is_file():
        badge = README_BADGE_RE.search(readme.read_text(encoding="utf-8"))
        if badge:
            advertised = int(badge.group(1))
            if advertised != count:
                errors.append(
                    f"README.md: badge advertises {advertised} skills but {count} SKILL.md files exist"
                )
            else:
                print(f"README badge matches: {advertised} skills")
        else:
            warnings.append("README.md: could not find a `skills-NN-*.svg` badge to cross-check")

    manifest = root / "claude-skills.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"claude-skills.json: invalid JSON ({exc})")
        else:
            entries = data.get("skills", [])
            if len(entries) != count:
                errors.append(
                    f"claude-skills.json: lists {len(entries)} skills but {count} SKILL.md files exist "
                    f"(re-run tools/build_manifest.py)"
                )
            empty = [e.get("path", "?") for e in entries if not e.get("description")]
            if empty:
                errors.append(
                    f"claude-skills.json: {len(empty)} entries have an empty description "
                    f"(first: {empty[0]})"
                )
            if not errors:
                print(f"claude-skills.json matches: {len(entries)} skills, all with descriptions")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for item in warnings:
            print(f"  ! {item}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for item in errors:
            print(f"  x {item}")
        print("\nFAILED")
        return 1

    print(f"\nOK -- {count} skills are installable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
