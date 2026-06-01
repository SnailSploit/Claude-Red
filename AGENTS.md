# Repository Guidance for Codex Agents

## Project purpose

`skills-red` is a cross-platform offensive-security skill library for Claude and Codex, forked from Claude Red. The repository ships portable `SKILL.md` files for authorized red-team, penetration-testing, bug-bounty, CTF, and security-research workflows.

## Safety boundaries

- Keep examples scoped to authorized testing and lab/CTF contexts.
- Do not add real victim infrastructure, credentials, customer data, or destructive defaults.
- Preserve responsible-disclosure and evidence-handling guidance when editing reporting or exploit content.

## Skill format

- Skills live at `Skills/<category>/<skill-name>/SKILL.md`.
- The folder name must match the frontmatter `name` value.
- Codex uses the frontmatter `name` and `description` for skill discovery; keep descriptions specific and trigger-rich.
- Prefer concise, operator-useful instructions over generic background.
- Use language tags on code blocks.

## Codex packaging expectations

- Codex installs skills as `$CODEX_HOME/skills/<skill-name>/SKILL.md` (default `$CODEX_HOME` is `~/.codex`).
- `./install.sh --platform codex` flattens category folders into individual Codex skill directories.
- `./install.sh --platform claude` preserves the Claude-compatible category tree.
- Regenerate manifests after skill or metadata changes:

```bash
python3 tools/build_manifest.py
```

## Verification

Before claiming completion for repository changes, run the narrowest relevant checks:

```bash
python3 tools/build_manifest.py
./install.sh --platform codex --dry-run
./install.sh --platform claude --dry-run
```

For shell changes, also run `bash -n install.sh`.
