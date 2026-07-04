# Skill Specter

Security scanner for Claude Code skills. Scans any skill before installation
for hidden threats: Unicode homoglyph spoofing, invisible instructions,
description/code mismatch, and known malware fingerprints.

## What it does

Every Claude Code skill is a text file of instructions that an agent blindly
executes. A malicious skill can hide commands invisible to humans, spoof tool
names with Unicode lookalikes, or lie about what it does. Skill Specter catches
these before installation.

## Usage

```
/scan-skill <path>         Pattern scan a skill (fast, ~200ms)
/scan-skill --ai <path>    AI deep scan (Claude headless review)
/scan-skill --fix <path>   Auto-fix issues + verify
/scan-skill --json <path>  Machine-readable JSON output
```

## How it works

### Detection layers

1. **Unicode spoofing** — maps Cyrillic α → Latin a, flags lookalike tool names
2. **Hidden content** — zero-width chars, invisible Unicode, HTML comments,
   base64 blobs, whitespace steganography
3. **Description mismatch** — does the skill do what it says? Catches
   curl-pipe-shell, eval injection, credential harvesting, etc.
4. **Fingerprint matching** — 20 known malware patterns (reverse shells,
   persistence, exfiltration, disk destruction)

### Scoring

| Range | Verdict |
|-------|---------|
| 0–19 | SAFE |
| 20–49 | CAUTION — minor concerns |
| 50–79 | WARNING — review carefully |
| 80–100 | BLOCKED — dangerous, do not install |

### AI Scan mode

When `--ai` is passed, Skill Specter invokes Claude Code in headless mode to:
- Adjudicate ambiguous pattern findings (real threat vs false positive)
- Discover novel threats the pattern scanner missed
- Provide reasoning for each verdict

## Pre-install hook

The install script registers a `PreToolUse` hook in `~/.claude/settings.json`
that gates every `Skill` invocation behind a scan. Skills scoring ≥80 are
blocked automatically.

## Files

```
~/.claude/skills/skill-specter/
├── SKILL.md              # This file
├── skill_specter.py      # Main scanner + CLI
├── install.sh            # One-line install script
├── fingerprints/
│   └── patterns.json     # Known malware pattern library (20 rules)
└── test_fixtures/        # Benign + malicious test samples
```

## Dependencies

- Python 3.10+ (stdlib only — no pip packages needed)
- Claude Code CLI (for AI scan mode only)

## Examples

```bash
# Quick scan
skill-specter scan ~/.claude/skills/suspicious-skill/

# Deep scan with AI review
skill-specter scan --ai ~/.claude/skills/suspicious-skill/

# Auto-fix + verify loop
skill-specter fix ~/.claude/skills/suspicious-skill/

# JSON output for scripts
skill-specter scan --json ~/.claude/skills/suspicious-skill/ | jq .

# Score only
skill-specter score ~/.claude/skills/suspicious-skill/
```

## Safety

Skill Specter itself is safe — it only reads files and runs static analysis.
No network calls, no file modifications unless `--fix` is explicitly used.
The AI scan mode uses Claude headless (offline from your main agent),
preventing any contamination of your working context.
