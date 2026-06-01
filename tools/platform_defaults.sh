# Shared platform install defaults for install.sh and manifest tooling.
# shellcheck shell=bash
# shellcheck disable=SC2034,SC2016,SC2088
#
# DEFAULT_* values are shell-expanded runtime defaults used by install.sh.
# MANIFEST_* values are literal distribution metadata roots emitted into
# generated *-skills.json indexes.

DEFAULT_CODEX_TARGET="${CODEX_HOME:-${HOME}/.codex}/skills"
DEFAULT_CLAUDE_TARGET="${HOME}/.claude/skills/skills-red"
DEFAULT_OPENCODE_TARGET="${OPENCODE_CONFIG_HOME:-${HOME}/.config/opencode}/skills"

MANIFEST_CODEX_INSTALL_ROOT='$CODEX_HOME/skills'
MANIFEST_CLAUDE_INSTALL_ROOT='~/.claude/skills/skills-red'
MANIFEST_OPENCODE_INSTALL_ROOT='~/.config/opencode/skills'
