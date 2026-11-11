#!/usr/bin/env python3
"""Regenerate claude-skills.json from the real SKILL.md frontmatter on disk.
Preserves the existing file's top-level metadata (name/version/license/homepage)
and the original category ordering; recomputes skills, categories, and counts."""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKILLS = ROOT / "Skills"
JSON = ROOT / "claude-skills.json"

try:
    import yaml
except ImportError:
    yaml = None

def description_section(text):
    """Fallback for older '## Metadata'-format files: pull the body of the
    '## Description' section (everything up to the next '## ' header)."""
    m = re.search(r'^##\s+Description\s*\n(.*?)(?=^\s*##\s+|\Z)', text, re.S | re.M | re.I)
    if not m:
        return ""
    body = m.group(1).strip()
    # collapse the paragraph into a single clean line
    return re.sub(r'\s+', ' ', body).strip()

def frontmatter(text):
    m = re.match(r'^---\n(.*?)\n---', text, re.S)
    if not m:
        return {}
    block = m.group(1)
    if yaml:
        try:
            data = yaml.safe_load(block) or {}
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    # fallback: minimal name/description parse
    out = {}
    nm = re.search(r'^name:\s*(.+)$', block, re.M)
    if nm: out['name'] = nm.group(1).strip().strip('"\'')
    dm = re.search(r'^description:\s*(.+)$', block, re.M | re.S)
    if dm: out['description'] = dm.group(1).strip().strip('"\'')
    return out

old = json.loads(JSON.read_text())

skills = []
for sk in sorted(SKILLS.rglob("SKILL.md")):
    rel = sk.relative_to(ROOT)
    parts = rel.parts            # Skills / <category> / <skillname> / SKILL.md
    category = parts[1] if len(parts) >= 4 else "uncategorized"
    raw = sk.read_text(encoding="utf-8", errors="replace")
    fm = frontmatter(raw)
    name = fm.get("name") or sk.parent.name
    desc = (fm.get("description") or "").strip()
    desc_source = "frontmatter"
    if not desc:
        desc = description_section(raw)
        desc_source = "section" if desc else "none"
    skills.append({
        "name": name,
        "category": category,
        "path": str(rel),
        "description": desc,
        "_src": desc_source,
    })

skills.sort(key=lambda s: (s["category"], s["name"]))

# tally description sources, then strip the private marker before serializing
from collections import Counter
src_counts = Counter(s.pop("_src") for s in skills)

categories = {}
for s in skills:
    categories.setdefault(s["category"], []).append(s["name"])
for c in categories:
    categories[c].sort()

result = {
    "name": old.get("name", "claude-red"),
    "version": old.get("version", "0.0.0"),
    "license": old.get("license", "MIT"),
    "homepage": old.get("homepage", ""),
    "categories": {c: categories[c] for c in sorted(categories)},
    "skills": skills,
    "skill_count": len(skills),
    "category_count": len(categories),
}

JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

# report
empty = [s["name"] for s in skills if not s["description"]]
print(f"yaml parser: {'PyYAML' if yaml else 'regex-fallback'}")
print(f"skills written : {result['skill_count']}")
print(f"categories     : {result['category_count']}")
print(f"desc sources   : frontmatter={src_counts.get('frontmatter',0)}  "
      f"section-fallback={src_counts.get('section',0)}  none={src_counts.get('none',0)}")
print(f"empty descrips : {len(empty)}")
if empty:
    print("  ->", ", ".join(empty))
# which names are new vs old
oldnames = {s['name'] for s in old['skills']}
newnames = {s['name'] for s in skills}
print("added vs old   :", ", ".join(sorted(newnames - oldnames)) or "none")
print("removed vs old :", ", ".join(sorted(oldnames - newnames)) or "none")
