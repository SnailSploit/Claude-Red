#!/usr/bin/env python3
"""Fail when generated root skill manifests are stale.

This helper intentionally regenerates the manifests in-place, then asks Git
whether the tracked manifest files changed. It keeps the source of truth in
``Skills/**/SKILL.md`` while making the root JSON distribution indexes hard to
forget during local review or CI.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = ("claude-skills.json", "codex-skills.json", "opencode-skills.json")
PLATFORM_DEFAULTS = ROOT / "tools" / "platform_defaults.sh"
MANIFEST_ROOT_RE = re.compile(
    r"^MANIFEST_(CODEX|CLAUDE|OPENCODE)_INSTALL_ROOT='([^']+)'$",
    re.MULTILINE,
)


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def manifest_install_roots() -> dict[str, str]:
    defaults = {
        platform.lower(): root
        for platform, root in MANIFEST_ROOT_RE.findall(PLATFORM_DEFAULTS.read_text(encoding="utf-8"))
    }
    missing = sorted({"codex", "claude", "opencode"} - defaults.keys())
    if missing:
        raise ValueError(f"{PLATFORM_DEFAULTS} missing manifest install root(s): {', '.join(missing)}")
    return defaults


def validate_manifest_install_paths() -> list[str]:
    roots = manifest_install_roots()
    errors: list[str] = []
    for manifest_name in MANIFESTS:
        manifest = json.loads((ROOT / manifest_name).read_text(encoding="utf-8"))
        platform = manifest["platform"]
        root = roots[platform]
        for skill in manifest["skills"]:
            expected = (
                f"{root}/{skill['category']}/{skill['name']}"
                if platform == "claude"
                else f"{root}/{skill['name']}"
            )
            if skill["install_path"] != expected:
                errors.append(
                    f"{manifest_name}: {skill['name']} install_path is "
                    f"{skill['install_path']!r}, expected {expected!r}"
                )
    return errors


def main() -> int:
    build = run([sys.executable, "tools/build_manifest.py"])
    if build.returncode != 0:
        sys.stdout.write(build.stdout)
        return build.returncode

    try:
        install_path_errors = validate_manifest_install_paths()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Manifest install-path validation failed: {exc}", file=sys.stderr)
        return 1
    if install_path_errors:
        print("Manifest install paths do not match install.sh defaults:", file=sys.stderr)
        for error in install_path_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    diff = run(["git", "diff", "--exit-code", "--", *MANIFESTS])
    if diff.returncode == 0:
        print("Generated skill manifests are fresh.")
        return 0

    sys.stdout.write(build.stdout)
    sys.stdout.write(diff.stdout)
    print(
        "Generated skill manifests were stale. "
        "Review and commit the regenerated *-skills.json files.",
        file=sys.stderr,
    )
    return diff.returncode


if __name__ == "__main__":
    raise SystemExit(main())
