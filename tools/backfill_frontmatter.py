#!/usr/bin/env python3
"""Backfill YAML frontmatter into legacy-format SKILL.md files.

Some files in ``Skills/`` still use the pre-conversion layout: a ``# SKILL:``
heading followed by ``## Metadata`` / ``## Description`` sections, with no YAML
frontmatter. Spec-compliant skill installers (``npx skills add``, Claude Skills)
require leading frontmatter with ``name`` and ``description``, so those files are
silently skipped and never installed.

This script derives both fields from data already present in the file and
prepends a frontmatter block, leaving the rest of the document untouched:

* ``name``        -- the skill directory name (matching the convention used by
                     every already-migrated skill in this repo).
* ``description`` -- the first paragraph of the ``## Description`` section,
                     collapsed to a single line.

Usage::

    python tools/backfill_frontmatter.py            # dry run, prints what would change
    python tools/backfill_frontmatter.py --write    # apply in place
    python tools/backfill_frontmatter.py --write --root path/to/repo

The script is idempotent: files that already carry a valid ``name`` +
``description`` frontmatter block are skipped.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\s*\n", re.DOTALL)
NAME_RE = re.compile(r"^name\s*:", re.MULTILINE)
DESCRIPTION_RE = re.compile(r"^description\s*:", re.MULTILINE)
SECTION_RE = re.compile(r"^##\s*Description\s*\n(.*?)(?=^##\s|\Z)", re.MULTILINE | re.DOTALL)
SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    return SLUG_RE.sub("-", value.lower()).strip("-")


def has_valid_frontmatter(text: str) -> bool:
    match = FRONTMATTER_RE.match(text)
    if not match:
        return False
    block = match.group(1)
    return bool(NAME_RE.search(block) and DESCRIPTION_RE.search(block))


def extract_description(text: str) -> str | None:
    match = SECTION_RE.search(text)
    if not match:
        return None
    # First paragraph only, whitespace collapsed to a single line.
    for paragraph in re.split(r"\n\s*\n", match.group(1).strip()):
        collapsed = " ".join(paragraph.split())
        if collapsed:
            return collapsed
    return None


def yaml_double_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_frontmatter(name: str, description: str) -> str:
    return f"---\nname: {name}\ndescription: {yaml_double_quote(description)}\n---\n\n"


def iter_skill_files(skills_dir: Path):
    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        yield skill_md


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true", help="apply changes in place (default: dry run)")
    parser.add_argument("--root", default=None, help="repository root (default: parent of tools/)")
    args = parser.parse_args()

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    skills_dir = root / "Skills"
    if not skills_dir.is_dir():
        print(f"error: {skills_dir} not found", file=sys.stderr)
        return 1

    total = 0
    already_ok = 0
    changed: list[str] = []
    failed: list[str] = []

    for skill_md in iter_skill_files(skills_dir):
        total += 1
        text = skill_md.read_text(encoding="utf-8")
        rel = skill_md.relative_to(root).as_posix()

        if has_valid_frontmatter(text):
            already_ok += 1
            continue

        name = slugify(skill_md.parent.name)
        description = extract_description(text)
        if not name or not description:
            failed.append(f"{rel} (name={name!r}, description found={bool(description)})")
            continue

        if args.write:
            skill_md.write_text(build_frontmatter(name, description) + text, encoding="utf-8", newline="\n")
            print(f"  + {rel}  name={name}  description={len(description)} chars")
        else:
            print(f"  ~ {rel}  name={name}  description={len(description)} chars")
        changed.append(rel)

    verb = "Updated" if args.write else "Would update"
    print()
    print(f"{verb} {len(changed)} of {total} SKILL.md files ({already_ok} already valid).")
    if failed:
        print(f"\nFAILED ({len(failed)}) -- could not derive frontmatter:")
        for item in failed:
            print(f"  ! {item}")
        return 1
    if not args.write and changed:
        print("\nDry run -- re-run with --write to apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
