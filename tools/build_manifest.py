#!/usr/bin/env python3
"""Generate Claude, Codex, and OpenCode skill manifests from the Skills/ tree.

Reads YAML frontmatter from each SKILL.md and emits compact JSON manifests
of all skills, grouped by category, for tooling that needs a machine-readable
index of the library.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "Skills"
MANIFESTS = {
    "claude": ROOT / "claude-skills.json",
    "codex": ROOT / "codex-skills.json",
    "opencode": ROOT / "opencode-skills.json",
}
PLATFORM_DEFAULTS = ROOT / "tools" / "platform_defaults.sh"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
OPENCODE_DESCRIPTION_LIMIT = 1024
MANIFEST_ROOT_RE = re.compile(r"^MANIFEST_(CODEX|CLAUDE|OPENCODE)_INSTALL_ROOT='([^']+)'$", re.MULTILINE)


def parse_frontmatter(text: str) -> dict[str, str]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    block = m.group(1)
    out: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []
    for line in block.splitlines():
        if not line.strip():
            continue
        if ":" in line and not line.startswith(" "):
            if current_key is not None:
                out[current_key] = "\n".join(buf).strip().strip('"')
                buf = []
            key, _, val = line.partition(":")
            current_key = key.strip()
            val = val.strip()
            if val:
                buf.append(val)
        else:
            buf.append(line.strip())
    if current_key is not None:
        out[current_key] = "\n".join(buf).strip().strip('"')
    return out


def normalize_opencode_description(description: str) -> str:
    """Return an OpenCode-compatible description without changing source SKILL.md."""
    if len(description) <= OPENCODE_DESCRIPTION_LIMIT:
        return description
    truncated = description[: OPENCODE_DESCRIPTION_LIMIT - 1].rsplit(" ", 1)[0].rstrip(",;:.- ")
    return f"{truncated}…"


def manifest_install_roots() -> dict[str, str]:
    defaults = {
        platform.lower(): root
        for platform, root in MANIFEST_ROOT_RE.findall(PLATFORM_DEFAULTS.read_text(encoding="utf-8"))
    }
    missing = sorted({"codex", "claude", "opencode"} - defaults.keys())
    if missing:
        raise ValueError(f"{PLATFORM_DEFAULTS} missing manifest install root(s): {', '.join(missing)}")
    return defaults


def validate_skill_metadata(skill_dir: Path, fm: dict[str, str], platform: str) -> list[str]:
    errors: list[str] = []
    name = fm.get("name", "").strip()
    description = fm.get("description", "").strip()
    if not fm:
        errors.append(f"{skill_dir}: missing YAML frontmatter")
    if not name:
        errors.append(f"{skill_dir}: missing frontmatter name")
    elif name != skill_dir.name:
        errors.append(f"{skill_dir}: frontmatter name '{name}' does not match folder '{skill_dir.name}'")
    elif platform == "opencode" and not SKILL_NAME_RE.fullmatch(name):
        errors.append(f"{skill_dir}: frontmatter name '{name}' is not OpenCode-compatible kebab-case")
    if not description:
        errors.append(f"{skill_dir}: missing frontmatter description")
    return errors


def build_manifest(platform: str) -> tuple[dict, list[str]]:
    homepage = "https://github.com/trewwwsec/skills-red"
    install_roots = manifest_install_roots()
    manifest: dict = {
        "name": "skills-red",
        "version": "0.2.0",
        "platform": platform,
        "license": "MIT",
        "homepage": homepage,
        "categories": {},
        "skills": [],
    }

    errors: list[str] = []
    seen_names: dict[str, Path] = {}

    for category_dir in sorted(SKILLS_DIR.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        manifest["categories"][category] = []
        for skill_dir in sorted(category_dir.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            fm = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
            errors.extend(validate_skill_metadata(skill_dir, fm, platform))
            skill_name = fm.get("name", skill_dir.name)
            if skill_name in seen_names:
                errors.append(
                    f"{skill_dir}: duplicate skill name '{skill_name}' also used by {seen_names[skill_name]}"
                )
            else:
                seen_names[skill_name] = skill_dir
            install_path = (
                f"{install_roots[platform]}/{category}/{skill_dir.name}"
                if platform == "claude"
                else f"{install_roots[platform]}/{skill_dir.name}"
            )
            entry = {
                "name": skill_name,
                "category": category,
                "path": str(skill_md.relative_to(ROOT)),
                "install_path": install_path,
                "description": normalize_opencode_description(fm.get("description", ""))
                if platform == "opencode"
                else fm.get("description", ""),
            }
            manifest["categories"][category].append(entry["name"])
            manifest["skills"].append(entry)

    manifest["skill_count"] = len(manifest["skills"])
    manifest["category_count"] = len(manifest["categories"])
    return manifest, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=("all", "codex", "claude", "opencode"),
        default="all",
        help="Which manifest to write (default: all).",
    )
    args = parser.parse_args()

    if not SKILLS_DIR.is_dir():
        print(f"Error: {SKILLS_DIR} not found", file=sys.stderr)
        return 1

    platforms = ("claude", "codex", "opencode") if args.platform == "all" else (args.platform,)
    all_errors: list[str] = []
    manifests: list[tuple[str, dict]] = []
    for platform in platforms:
        manifest, errors = build_manifest(platform)
        manifests.append((platform, manifest))
        all_errors.extend(errors)

    if all_errors:
        for error in all_errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    for platform, manifest in manifests:
        out = MANIFESTS[platform]
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(
            f"Wrote {out} with {manifest['skill_count']} skills "
            f"across {manifest['category_count']} categories."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
