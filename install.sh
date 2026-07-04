#!/usr/bin/env bash
# Skill Specter — one-line install
# Usage: curl -sSL https://raw.githubusercontent.com/xcode4tux/skill-specter/main/install.sh | bash
# Or local: bash install.sh

set -euo pipefail

SKILL_DIR="${HOME}/.claude/skills/skill-specter"
INSTALL_DIR="${SKILL_DIR}"

echo "🔍 Skill Specter — Security Scanner for Claude Code Skills"
echo ""

# If running from the repo itself, use current directory
if [[ -f "./skill_specter.py" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    echo "→ Installing from local repo: ${SCRIPT_DIR}"
    mkdir -p "${SKILL_DIR}"
    cp "${SCRIPT_DIR}/skill_specter.py" "${SKILL_DIR}/"
    cp -r "${SCRIPT_DIR}/fingerprints" "${SKILL_DIR}/" 2>/dev/null || true
    cp "${SCRIPT_DIR}/SKILL.md" "${SKILL_DIR}/" 2>/dev/null || true
else
    echo "→ Cloning from GitHub..."
    git clone https://github.com/xcode4tux/skill-specter.git /tmp/skill-specter-install
    mkdir -p "${SKILL_DIR}"
    cp /tmp/skill-specter-install/skill_specter.py "${SKILL_DIR}/"
    cp -r /tmp/skill-specter-install/fingerprints "${SKILL_DIR}/" 2>/dev/null || true
    cp /tmp/skill-specter-install/SKILL.md "${SKILL_DIR}/" 2>/dev/null || true
    rm -rf /tmp/skill-specter-install
fi

chmod +x "${SKILL_DIR}/skill_specter.py"

# Create symlink for CLI access
mkdir -p "${HOME}/.local/bin"
ln -sf "${SKILL_DIR}/skill_specter.py" "${HOME}/.local/bin/skill-specter"

# Register the pre-install hook in Claude Code settings
HOOKS_FILE="${HOME}/.claude/settings.json"

register_hook() {
    local hook_content
    hook_content=$(cat <<'HOOKEOF'
{
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Skill",
                "command": "python3 ${HOME}/.claude/skills/skill-specter/skill_specter.py scan --json ${CLAUDE_TOOL_INPUT} 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); s=max((r['score'] for r in d),default=0); exit(0 if s<80 else 1)\" && echo 'SKILL_SCAN:PASS' || (echo 'SKILL_SCAN:BLOCKED — score >= 80, refusing to install' >&2 && exit 1)"
            }
        ]
    }
}
HOOKEOF
)

    # Merge with existing settings if hooks.json exists
    if [[ -f "${HOOKS_FILE}" ]]; then
        python3 << 'PYEOF'
import json, sys
from pathlib import Path

settings_file = Path.home() / ".claude/settings.json"
try:
    with open(settings_file) as f:
        settings = json.load(f)
except (json.JSONDecodeError, FileNotFoundError):
    settings = {}

hooks = settings.get("hooks", {})
pretooluse = hooks.get("PreToolUse", [])

# Check if skill-specter hook already registered
already = any(
    "skill-specter" in h.get("command", "") or "skill_specter" in h.get("command", "")
    for h in pretooluse
)

if not already:
    pretooluse.append({
        "matcher": "Skill",
        "command": f"python3 {Path.home()}/.claude/skills/skill-specter/skill_specter.py scan --json $CLAUDE_TOOL_INPUT 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); s=max((r['score'] for r in d),default=0); exit(0 if s<80 else 1)\" && echo 'SKILL_SCAN:PASS' || (echo 'SKILL_SCAN:BLOCKED — score >= 80, refusing to install' >&2 && exit 1)"
    })
    hooks["PreToolUse"] = pretooluse
    settings["hooks"] = hooks

    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)
    print("✓ Pre-install hook registered in settings.json")
else:
    print("✓ Pre-install hook already registered")
PYEOF
    else
        # Create new settings file
        cat > "${HOOKS_FILE}" << 'EOF'
{
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Skill",
                "command": "python3 ${HOME}/.claude/skills/skill-specter/skill_specter.py scan --json ${CLAUDE_TOOL_INPUT} 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); s=max((r['score'] for r in d),default=0); exit(0 if s<80 else 1)\" && echo 'SKILL_SCAN:PASS' || (echo 'SKILL_SCAN:BLOCKED — score >= 80, refusing to install' >&2 && exit 1)"
            }
        ]
    }
}
EOF
        echo "✓ settings.json created with pre-install hook"
    fi
}

# Ask before registering hook
echo ""
echo "→ Register pre-install hook? (scans skills before Claude Code installs them)"
echo "  This adds a PreToolUse hook to ~/.claude/settings.json"
read -p "  [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    register_hook
fi

echo ""
echo "✅ Skill Specter installed!"
echo ""
echo "Usage:"
echo "  skill-specter scan ~/.claude/skills/some-skill/"
echo "  skill-specter scan --ai ~/.claude/skills/some-skill/"
echo "  skill-specter fix ~/.claude/skills/some-skill/"
echo "  skill-specter score ~/.claude/skills/some-skill/"
echo ""
echo "The pre-install hook will automatically scan any skill before"
echo "Claude Code installs it. Skills scoring >= 80 are blocked."
