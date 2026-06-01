#!/usr/bin/env bash
# codex-red / claude-red installer
# Copies offensive security skills into a Codex or Claude skills directory.
#
# Usage:
#   ./install.sh                                # interactive Codex install
#   ./install.sh --platform codex              # install flattened Codex skills
#   ./install.sh --platform claude             # install Claude category tree
#   ./install.sh --target ~/.codex/skills      # explicit target
#   ./install.sh --category web                # one category only
#   ./install.sh --target DIR --category web   # combined
#   ./install.sh --list                        # list available categories
#   ./install.sh --dry-run                     # show what would be copied
#
# Default Codex target: ~/.codex/skills
# Default Claude target: ~/.claude/skills/claude-red

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$SCRIPT_DIR/Skills"
DEFAULT_CODEX_TARGET="${CODEX_HOME:-${HOME}/.codex}/skills"
DEFAULT_CLAUDE_TARGET="${HOME}/.claude/skills/claude-red"

PLATFORM="codex"
TARGET=""
CATEGORY=""
DRY_RUN=0
LIST_ONLY=0
SKILL_COUNT=0

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
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

validate_codex_metadata() {
  local source_root="$1"
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
    if ! printf '%s\n' "$frontmatter" | grep -q '^description: .'; then
      echo "Error: $skill_md missing frontmatter description" >&2
      errors=$((errors + 1))
    fi
    case " $seen_names " in
      *" $skill_name "*)
        echo "Error: duplicate Codex skill folder name '$skill_name'" >&2
        errors=$((errors + 1))
        ;;
    esac
    seen_names="$seen_names $skill_name"
  done < <(find "$source_root" -mindepth 2 -maxdepth 3 -name SKILL.md -print0 | sort -z)

  if [ "$errors" -ne 0 ]; then
    exit 1
  fi
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

install_codex() {
  local source_root="$1"
  local target_root="$2"
  local copied=0

  if [ "$DRY_RUN" -ne 1 ]; then
    mkdir -p "$target_root"
  fi
  while IFS= read -r -d '' skill_md; do
    skill_dir=$(dirname "$skill_md")
    skill_name=$(basename "$skill_dir")
    dest="$target_root/$skill_name"
    if [ "$DRY_RUN" -eq 1 ]; then
      printf "  %s -> %s\n" "$skill_dir" "$dest"
    else
      copy_tree "$skill_dir" "$dest"
    fi
    copied=$((copied + 1))
  done < <(find "$source_root" -mindepth 2 -maxdepth 3 -name SKILL.md -print0 | sort -z)

  SKILL_COUNT="$copied"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --platform)
      PLATFORM="$2"
      case "$PLATFORM" in codex|claude) ;; *) echo "Error: --platform must be codex or claude" >&2; exit 1 ;; esac
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
  if [ "$PLATFORM" = "codex" ]; then
    DEFAULT_TARGET="$DEFAULT_CODEX_TARGET"
  else
    DEFAULT_TARGET="$DEFAULT_CLAUDE_TARGET"
  fi
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

if [ "$PLATFORM" = "claude" ]; then
  if [ -n "$CATEGORY" ]; then
    DEST="$TARGET/$CATEGORY"
  else
    DEST="$TARGET"
  fi
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

if [ "$PLATFORM" = "codex" ]; then
  validate_codex_metadata "$SOURCE"
  install_codex "$SOURCE" "$DEST"
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
if [ "$PLATFORM" = "codex" ]; then
  echo "Restart Codex to pick up new skills."
else
  echo "Claude should now auto-discover them on next session start."
fi
