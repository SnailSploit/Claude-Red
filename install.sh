#!/usr/bin/env bash
# skills-red installer
# Copies offensive security skills into a Codex, Claude, or OpenCode skills directory.
#
# Usage:
#   ./install.sh                                # interactive Codex install
#   ./install.sh --platform codex              # install Codex skills under skills-red category tree
#   ./install.sh --platform claude             # install Claude category tree
#   ./install.sh --platform opencode           # install OpenCode skills under skills-red category tree
#   ./install.sh --target ~/.codex/skills/skills-red  # explicit target
#   ./install.sh --category web                # one category only
#   ./install.sh --target DIR --category web   # combined
#   ./install.sh --list                        # list available categories
#   ./install.sh --dry-run                     # show what would be copied
#
# Default Codex target: ~/.codex/skills/skills-red
# Default Claude target: ~/.claude/skills/skills-red
# Default OpenCode target: ~/.config/opencode/skills/skills-red

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$SCRIPT_DIR/Skills"
# shellcheck source=tools/platform_defaults.sh
. "$SCRIPT_DIR/tools/platform_defaults.sh"

PLATFORM="codex"
TARGET=""
CATEGORY=""
DRY_RUN=0
LIST_ONLY=0
SKILL_COUNT=0

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

list_categories() {
  echo "Available categories:"
  for d in "$SKILLS_DIR"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    count=$(find "$d" -name SKILL.md | wc -l | tr -d ' ')
    printf "  %-20s %s skill(s)\n" "$name" "$count"
  done
}

validate_skill_metadata() {
  local source_root="$1"
  local platform="$2"
  local seen_names=""
  local errors=0

  while IFS= read -r -d '' skill_md; do
    skill_dir=$(dirname "$skill_md")
    skill_name=$(basename "$skill_dir")
    first_line=$(sed -n '1p' "$skill_md")
    frontmatter=$(sed -n '2,/^---$/p' "$skill_md" | sed '$d')
    closing_line=$(sed -n '2,/^---$/p' "$skill_md" | tail -1)

    if [ "$first_line" != "---" ] || [ "$closing_line" != "---" ]; then
      echo "Error: $skill_md missing leading YAML frontmatter block" >&2
      errors=$((errors + 1))
    fi
    if ! printf '%s\n' "$frontmatter" | grep -q "^name: $skill_name$"; then
      echo "Error: $skill_md frontmatter name must match folder '$skill_name'" >&2
      errors=$((errors + 1))
    fi
    if [ "$platform" = "opencode" ] && ! printf '%s\n' "$skill_name" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$'; then
      echo "Error: $skill_md skill name must be lowercase kebab-case for OpenCode" >&2
      errors=$((errors + 1))
    fi
    description=$(printf '%s\n' "$frontmatter" | sed -n 's/^description: //p' | head -1 | sed 's/^\"//; s/\"$//')
    if [ -z "$description" ]; then
      echo "Error: $skill_md missing frontmatter description" >&2
      errors=$((errors + 1))
    fi
    case " $seen_names " in
      *" $skill_name "*)
        echo "Error: duplicate skill folder name '$skill_name'" >&2
        errors=$((errors + 1))
        ;;
    esac
    seen_names="$seen_names $skill_name"
  done < <(find "$source_root" -mindepth 2 -maxdepth 3 -name SKILL.md -print0 | sort -z)

  if [ "$errors" -ne 0 ]; then
    exit 1
  fi
}

normalize_opencode_skill() {
  local skill_file="$1"
  python3 - "$skill_file" <<'PY'
import json
import re
import sys
from pathlib import Path

LIMIT = 1024
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
if not match:
    raise SystemExit(0)
frontmatter = match.group(1)
desc_match = re.search(r'^description:\s*(.*)$', frontmatter, re.MULTILINE)
if not desc_match:
    raise SystemExit(0)
raw = desc_match.group(1).strip()
try:
    description = json.loads(raw) if raw.startswith('"') else raw
except json.JSONDecodeError:
    description = raw.strip('"')
if len(description) <= LIMIT:
    raise SystemExit(0)
truncated = description[: LIMIT - 1].rsplit(" ", 1)[0].rstrip(",;:.- ") + "…"
replacement = "description: " + json.dumps(truncated, ensure_ascii=False)
frontmatter = re.sub(r'^description:\s*.*$', replacement, frontmatter, count=1, flags=re.MULTILINE)
path.write_text("---\n" + frontmatter + text[match.end() - 4 :], encoding="utf-8")
PY
}

copy_tree() {
  local source="$1"
  local dest="$2"
  mkdir -p "$dest"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a "$source/" "$dest/"
  else
    cp -R "$source/." "$dest/"
    echo "Copied via cp (install rsync for progress info)."
  fi
}

install_platform_skills() {
  local source_root="$1"
  local target_root="$2"
  local platform="$3"
  local copied=0

  if [ "$DRY_RUN" -ne 1 ]; then
    mkdir -p "$target_root"
  fi
  while IFS= read -r -d '' skill_md; do
    skill_dir=$(dirname "$skill_md")
    skill_name=$(basename "$skill_dir")
    category="$(basename "$(dirname "$skill_dir")")"
    dest="$target_root/$category/$skill_name"
    if [ "$DRY_RUN" -eq 1 ]; then
      printf "  %s -> %s\n" "$skill_dir" "$dest"
    else
      copy_tree "$skill_dir" "$dest"
      if [ "$platform" = "opencode" ]; then
        normalize_opencode_skill "$dest/SKILL.md"
      fi
    fi
    copied=$((copied + 1))
  done < <(find "$source_root" -mindepth 2 -maxdepth 3 -name SKILL.md -print0 | sort -z)

  SKILL_COUNT="$copied"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --platform)
      PLATFORM="$2"
      case "$PLATFORM" in codex|claude|opencode) ;; *) echo "Error: --platform must be codex, claude, or opencode" >&2; exit 1 ;; esac
      shift 2
      ;;
    --target)   TARGET="$2"; shift 2 ;;
    --category) CATEGORY="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    --list)     LIST_ONLY=1; shift ;;
    -h|--help)  usage 0 ;;
    *)          echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

if [ "$LIST_ONLY" -eq 1 ]; then
  list_categories
  exit 0
fi

if [ ! -d "$SKILLS_DIR" ]; then
  echo "Error: Skills directory not found at $SKILLS_DIR" >&2
  exit 1
fi

if [ -z "$TARGET" ]; then
  case "$PLATFORM" in
    codex) DEFAULT_TARGET="$DEFAULT_CODEX_TARGET" ;;
    claude) DEFAULT_TARGET="$DEFAULT_CLAUDE_TARGET" ;;
    opencode) DEFAULT_TARGET="$DEFAULT_OPENCODE_TARGET" ;;
  esac
  if [ -t 0 ]; then
    read -r -p "Install target [$DEFAULT_TARGET]: " TARGET || true
  fi
  TARGET="${TARGET:-$DEFAULT_TARGET}"
fi

if [ -n "$CATEGORY" ]; then
  if [ ! -d "$SKILLS_DIR/$CATEGORY" ]; then
    echo "Error: Category '$CATEGORY' not found." >&2
    echo "" >&2
    list_categories >&2
    exit 1
  fi
  SOURCE="$SKILLS_DIR/$CATEGORY"
else
  SOURCE="$SKILLS_DIR"
fi

if [ "$PLATFORM" = "codex" ] || [ "$PLATFORM" = "opencode" ]; then
  DEST="$TARGET"
elif [ -n "$CATEGORY" ]; then
  DEST="$TARGET/$CATEGORY"
else
  DEST="$TARGET"
fi

echo "Platform: $PLATFORM"
echo "Source:   $SOURCE"
echo "Target:   $DEST"
echo

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] Would copy:"
fi

if [ "$PLATFORM" = "codex" ] || [ "$PLATFORM" = "opencode" ]; then
  validate_skill_metadata "$SOURCE" "$PLATFORM"
  install_platform_skills "$SOURCE" "$DEST" "$PLATFORM"
  skill_count="$SKILL_COUNT"
else
  if [ "$DRY_RUN" -eq 1 ]; then
    find "$SOURCE" -name SKILL.md | sed "s|^$SOURCE|  $DEST|"
    skill_count=$(find "$SOURCE" -name SKILL.md | wc -l | tr -d ' ')
  else
    copy_tree "$SOURCE" "$DEST"
    skill_count=$(find "$DEST" -name SKILL.md | wc -l | tr -d ' ')
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  echo "Dry run complete: $skill_count skill(s) selected."
  exit 0
fi

echo
echo "Installed $skill_count skill(s) to $DEST"
case "$PLATFORM" in
  codex) echo "Restart Codex to pick up new skills." ;;
  claude) echo "Claude should now auto-discover them on next session start." ;;
  opencode) echo "Restart OpenCode, or start a new session, to refresh available skills." ;;
esac
