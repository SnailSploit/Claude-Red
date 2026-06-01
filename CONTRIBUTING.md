# Contributing to codex-red

Thanks for contributing. This guide explains the skill format, the review process, and the conventions to keep the library coherent as it grows.

## Quick Rules

1. **One skill, one surface.** Prefer focused skills (`offensive-kerberoasting`) over monolithic overviews (`offensive-active-directory`).
2. **YAML frontmatter is required.** Skills without it won't load via the Codex Skills system (and remain portable to Claude Skills).
3. **Cite sources.** Every technique should be attributable. Link CVEs, advisories, original research.
4. **No unauthorized targeting.** Don't include hardcoded victim domains, real customer data, or credentials.
5. **Use code blocks with language tags.** It's how Claude (and humans) parse them best.

---

## Skill Format

A skill lives at:

```
Skills/<category>/<skill-folder>/SKILL.md
```

The folder name **must** match the `name:` field in the frontmatter.

### Frontmatter (required)

```yaml
---
name: offensive-<bug-class-or-domain>
description: "One paragraph (50–500 words). State the surface, the techniques covered, and when to use this skill. Codex uses this for trigger matching — be specific about scenarios, tools, and sub-topics."
---
```

The `description` is what Codex matches against. Make it dense with relevant terms an operator would mention. Avoid marketing language.

### Body Structure (recommended)

```markdown
# <Short Skill Title>

<One-paragraph framing. Why this matters, what makes it distinct.>

## Quick Workflow

1. <Numbered, ordered steps an operator follows in the field>

---

## <Section per phase or technique cluster>

<Concrete, copy-paste commands or code blocks. Annotate the why.>

---

## Detection / Defender View

<Optional but valuable — what defenders will see, common evasions.>

---

## Engagement Cheatsheet

<A short copy-paste-ready sequence summarizing the methodology.>

---

## Key References

- MITRE ATT&CK / CWE / OWASP IDs
- Canonical research papers, conference talks
- Tool docs, advisory URLs
- Source: link to upstream checklist if applicable
```

### Style Guide

- **Voice:** technical, second-person ("you"), present tense
- **Length:** 200–800 lines is typical; aim for depth in one surface, not breadth across many
- **Code blocks:** always specify the language (`bash`, `python`, `c`, `powershell`, `sql`, `yaml`, `http`)
- **Tables:** use for compact reference (CVE → exploitation, capability → escape, etc.)
- **No emoji** unless used as visual markers in tables (✓ ✗ ⚠) and only sparingly

---

## Adding a New Skill

1. Pick the right category folder. If none fits, propose a new one in your PR description.
2. Create `Skills/<category>/<skill-name>/SKILL.md`.
3. Write the frontmatter and body following the structure above.
4. Update [`README.md`](README.md) — add the skill to the relevant category table.
5. Update [`CHANGELOG.md`](CHANGELOG.md) under the next version.
6. Update the generated manifests (`claude-skills.json` and `codex-skills.json`) by running `python tools/build_manifest.py`.
7. Run any local lint:
   ```bash
   ./tools/check-skill.sh Skills/<category>/<skill-name>/SKILL.md
   ```

## Modifying an Existing Skill

- Preserve the `name:` field (it's a public identifier; renames are breaking changes)
- Note the edit briefly in CHANGELOG.md
- For substantive rewrites, link the prior version's SHA so reviewers can diff

## Splitting a Monolithic Skill

When a skill grows beyond one surface (e.g. `offensive-wifi` covering WPA2, WPA3, BLE, Zigbee), split it:

1. Keep the original as a brief overview that points to the new focused skills
2. Move detailed content into new per-surface skills
3. Update README, CHANGELOG, and the manifest

The roadmap in README tracks current splits.

## Review Process

Pull requests are reviewed for:

- Technical accuracy (does this work? is it current?)
- Clarity (would a competent operator understand and execute?)
- Scope (one surface, not three)
- Attribution (sources cited?)
- Safety (no real targets, no live secrets, no malicious helpers)

Expect one round of review. Maintainers may request edits before merging.

---

## What We Won't Accept

- Skills that hardcode real victim infrastructure
- Tooling that has destructive defaults without warnings
- Bypasses for vendor-mandated security telemetry without legitimate red team context
- Content under non-MIT-compatible licenses
- AI-generated skills without operator review (use Codex or Claude to draft, then verify and edit)

---

## Questions

Open a GitHub Discussion before a large PR so the maintainers can confirm the direction. For sensitive findings (a leaked credential in an example, etc.), see [SECURITY.md](SECURITY.md).
