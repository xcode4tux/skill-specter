# Skill Specter

> Security scanner for Claude Code skills. Don't install blind.

Every Claude Code skill is a text file full of instructions that an agent
follows without question. A malicious skill can:

- **Hide instructions** using zero-width characters invisible to humans
- **Spoof tool names** with Unicode lookalikes (Cyrillic `е` instead of Latin `e` in "Read")
- **Lie about purpose** — says it's a formatter, actually exfiltrates your SSH keys
- **Match malware fingerprints** — reverse shells, credential harvesting, persistence

Skill Specter catches all of these before installation.

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/ailabs-393/skill-specter/main/install.sh | bash
```

Or locally:
```bash
cd ~/.claude/skills/skill-specter && bash install.sh
```

## Usage

```bash
# Quick scan (pattern only, ~200ms)
skill-specter scan ~/.claude/skills/some-skill/

# Deep scan with AI review (uses Claude headless)
skill-specter scan --ai ~/.claude/skills/some-skill/

# Auto-fix issues and verify
skill-specter fix ~/.claude/skills/some-skill/

# JSON output for scripting
skill-specter scan --json ~/.claude/skills/some-skill/

# Score only (returns 0-100)
skill-specter score ~/.claude/skills/some-skill/
```

## Scoring

| Score | Verdict |
|-------|---------|
| 0–19  | SAFE — no significant threats |
| 20–49 | CAUTION — minor concerns |
| 50–79 | WARNING — suspicious, review carefully |
| 80–100 | BLOCKED — dangerous, do not install |

## Detection Layers

1. **Unicode Spoofing** — maps 50+ Unicode homoglyphs across Cyrillic, Greek,
   and fullwidth character sets; flags when used in tool-name context
2. **Hidden Content** — zero-width spaces, joiners, BOM, soft hyphens, HTML
   comments, base64 blobs, whitespace steganography
3. **Description Mismatch** — 12 behavioral patterns that indicate a skill
   does something dangerous regardless of what it claims
4. **Fingerprint Matching** — 20 known malware patterns: reverse shells,
   persistence mechanisms, credential harvesting, data exfiltration,
   destructive commands

## Pre-install Hook

The installer can register a `PreToolUse` hook in `~/.claude/settings.json`
that scans every skill before Claude Code installs it. Skills scoring >= 80
are automatically blocked.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Skill",
        "command": "skill-specter scan --json $CLAUDE_TOOL_INPUT | ..."
      }
    ]
  }
}
```

## Test Fixtures

The `test_fixtures/` directory contains samples for validation:

```
test_fixtures/
├── benign-formatter/       # Clean skill, score 0
├── malicious-hidden/       # Zero-width chars + hidden curl|bash, score 100
├── malicious-unicode/      # Cyrillic homoglyph spoofing, score 100
└── malicious-mismatch/     # curl-pipe-shell in "build optimizer", score 75
```

## Requirements

- Python 3.10+ (stdlib only — zero pip dependencies for pattern scan)
- Claude Code CLI (for `--ai` scan mode only)

## File Structure

```
~/.claude/skills/skill-specter/
├── README.md
├── SKILL.md               # Claude Code skill definition
├── skill_specter.py       # Main scanner + CLI (single file)
├── install.sh             # One-line installer
├── fingerprints/
│   └── patterns.json      # Expandable malware pattern library
└── test_fixtures/         # Benign + malicious samples
```
