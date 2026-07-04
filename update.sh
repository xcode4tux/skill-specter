#!/usr/bin/env bash
# Skill Specter — auto-update script
# Called by SessionStart hook. Pulls latest scanner code + fingerprint DB.
# Configure remote:  git -C ~/.claude/skills/skill-specter remote add origin <url>
set -euo pipefail

SKILL_DIR="${HOME}/.claude/skills/skill-specter"
UPDATE_LOG="${SKILL_DIR}/.update-log"
LAST_CHECK="${SKILL_DIR}/.last-check"

# --- Don't check more than once per day (86400 seconds) ---
now=$(date +%s)
if [[ -f "${LAST_CHECK}" ]]; then
    last=$(cat "${LAST_CHECK}" 2>/dev/null || echo 0)
    elapsed=$((now - last))
    if [[ ${elapsed} -lt 86400 ]]; then
        exit 0  # checked recently, skip
    fi
fi

echo "$(date -Iseconds): Checking for updates..." >> "${UPDATE_LOG}"

# --- Git pull from origin if configured ---
if git -C "${SKILL_DIR}" remote get-url origin &>/dev/null; then
    # Stash any local changes, pull, then pop
    if ! git -C "${SKILL_DIR}" diff --quiet 2>/dev/null; then
        git -C "${SKILL_DIR}" stash push -m "auto-update-$(date +%s)" >> "${UPDATE_LOG}" 2>&1 || true
    fi

    if git -C "${SKILL_DIR}" pull --rebase origin master 2>>"${UPDATE_LOG}"; then
        echo "$(date -Iseconds): Updated successfully" >> "${UPDATE_LOG}"
    else
        echo "$(date -Iseconds): Update check failed (no network, no remote, or conflict)" >> "${UPDATE_LOG}"
    fi
else
    # No remote configured — skip git pull, just note it
    echo "$(date -Iseconds): No remote configured — git pull skipped" >> "${UPDATE_LOG}"
fi

# --- Check for fingerprint DB updates from a separate URL ---
# Users can set SKILL_SPECTER_FINGERPRINTS_URL to an alternate patterns.json
FINGERPRINTS_URL="${SKILL_SPECTER_FINGERPRINTS_URL:-}"
if [[ -n "${FINGERPRINTS_URL}" ]]; then
    curl -sL --max-time 10 "${FINGERPRINTS_URL}" \
        -o "${SKILL_DIR}/fingerprints/patterns.json.new" 2>/dev/null && \
    python3 -c "import json; json.load(open('${SKILL_DIR}/fingerprints/patterns.json.new'))" 2>/dev/null && \
    mv "${SKILL_DIR}/fingerprints/patterns.json.new" "${SKILL_DIR}/fingerprints/patterns.json" && \
    echo "$(date -Iseconds): Fingerprint DB updated from ${FINGERPRINTS_URL}" >> "${UPDATE_LOG}" || \
    rm -f "${SKILL_DIR}/fingerprints/patterns.json.new"
fi

# --- Mark check time ---
echo "${now}" > "${LAST_CHECK}"
