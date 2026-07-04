#!/usr/bin/env python3
"""
Skill Specter — security scanner for Claude Code skills.

Detects:
  1. Unicode homoglyph spoofing (Cyrillic/Greek lookalikes in tool names)
  2. Hidden instructions (zero-width chars, invisible Unicode, base64 blobs)
  3. Description/code mismatch (skill says X, code does Y)
  4. Known malware fingerprint matching

Two modes:
  - pattern  (default): fast static analysis, ~200ms
  - ai       (--ai):    Claude Code headless deep review for ambiguous findings

Score: 0 = safe, 100 = dangerous / blocked.

Usage:
  skill-specter scan <path>          # pattern scan
  skill-specter scan --ai <path>     # AI deep scan
  skill-specter fix <path>           # auto-fix + verify loop
  skill-specter score <path>         # score only, JSON output
"""

import argparse
import json
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────
SKILL_DIR = Path(__file__).resolve().parent
FINGERPRINTS_PATH = SKILL_DIR / "fingerprints" / "patterns.json"

# ── Unicode homoglyph mapping ──────────────────────────────────────────────
# Latin char → list of confusable Unicode chars from Cyrillic, Greek, etc.
HOMOGLYPHS = {
    "a": ["а", "α", "ａ"],  # Cyrillic a, Greek alpha, fullwidth a
    "A": ["А", "Α", "Ａ"],
    "b": ["Ь", "ｂ"],        # Cyrillic soft sign (looks like b)
    "B": ["В", "Β", "Ｂ"],   # Cyrillic ve, Greek beta
    "c": ["с", "ϲ", "ｃ"],  # Cyrillic es, lunate sigma
    "C": ["С", "Ϲ", "Ｃ"],  # Cyrillic es
    "d": ["ԁ", "ɗ", "ｄ"],
    "e": ["е", "ε", "ｅ"],   # Cyrillic ie, Greek epsilon
    "E": ["Е", "Ε", "Ｅ"],   # Cyrillic ie
    "f": ["ｆ"],
    "g": ["ɡ", "ｇ"],
    "h": ["һ", "ｈ"],        # Cyrillic shha
    "H": ["Н", "Η", "Ｈ"],   # Cyrillic en, Greek eta
    "i": ["і", "ι", "ｉ"],  # Cyrillic i, Greek iota
    "I": ["І", "Ι", "Ｉ"],
    "j": ["ј", "ϳ", "ｊ"],  # Cyrillic je
    "J": ["Ј", "Ϳ", "Ｊ"],
    "k": ["κ", "ｋ"],        # Greek kappa
    "K": ["Κ", "Ｋ"],        # Greek kappa
    "l": ["ӏ", "ｌ"],
    "m": ["ｍ"],
    "M": ["М", "Μ", "Ｍ"],   # Cyrillic em, Greek mu
    "n": ["ｎ"],
    "o": ["о", "ο", "օ", "ｏ"],  # Cyrillic o, Greek omicron
    "O": ["О", "Ο", "Ｏ"],
    "p": ["р", "ρ", "ｐ"],   # Cyrillic er, Greek rho
    "P": ["Р", "Ρ", "Ｐ"],   # Cyrillic er, Greek rho
    "q": ["ｑ"],
    "r": ["г", "ｒ"],        # Cyrillic ghe
    "s": ["ѕ", "ｓ"],        # Cyrillic dze
    "S": ["Ѕ", "Ｓ"],
    "t": ["т", "τ", "ｔ"],   # Cyrillic te, Greek tau
    "T": ["Т", "Τ", "Ｔ"],
    "u": ["υ", "ｕ"],
    "v": ["ν", "ｖ"],
    "w": ["ѡ", "ｗ"],
    "x": ["х", "χ", "ｘ"],   # Cyrillic kha, Greek chi
    "X": ["Х", "Χ", "Ｘ"],
    "y": ["у", "γ", "ｙ"],   # Cyrillic u, Greek gamma
    "Y": ["Υ", "Υ", "Ｙ"],
    "z": ["ｚ"],
    "Z": ["Ζ", "Ｚ"],
}

# Build reverse map: spoofed_char → which_latin_char
SPOOF_TO_LATIN: dict[str, str] = {}
for latin, spoofed_list in HOMOGLYPHS.items():
    for ch in spoofed_list:
        SPOOF_TO_LATIN[ch] = latin

# ── Known-dangerous tool names (Claude Code built-in tools) ─────────────────
DANGEROUS_TOOLS = {
    "Bash", "Read", "Write", "Edit", "Glob", "Grep",
    "Agent", "Task", "WebFetch", "WebSearch", "Skill",
    "NotebookEdit", "EnterPlanMode", "ExitPlanMode",
}

# Patterns for tool-call detection in skill text
TOOL_NAME_PATTERN = re.compile(
    r'\b(?:Bash|Read|Write|Edit|Glob|Grep|Agent|Task|'
    r'WebFetch|WebSearch|Skill|NotebookEdit|EnterPlanMode|ExitPlanMode|'
    r'bash|read|write|edit|glob|grep)\b'
)

# ── Hidden content detectors ────────────────────────────────────────────────

# Zero-width characters
ZERO_WIDTH_CHARS = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "­": "SOFT HYPHEN",
    "͏": "COMBINING GRAPHEME JOINER",
    "؜": "ARABIC LETTER MARK",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
}

# Other suspicious Unicode ranges
SUSPICIOUS_UNICODE = [
    (range(0x2000, 0x200F + 1), "General Punctuation (invisible)"),
    (range(0x2028, 0x2029 + 1), "Line/Paragraph Separator"),
    (range(0x202A, 0x202E + 1), "Bidirectional Text Control"),
    (range(0x2066, 0x2069 + 1), "Bidirectional Isolation"),
]

# Base64 pattern (potential encoded payloads)
BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.MULTILINE
)

# HTML/XML comments (hidden in rendered markdown)
HTML_COMMENT_PATTERN = re.compile(r'<!--.*?-->', re.DOTALL)

# Excessive whitespace steganography
# Only flag trailing whitespace (after content ends) or all-whitespace lines.
# Structural alignment (text → whitespace → more text) is NOT steganography.
STEG_WHITESPACE_PATTERN = re.compile(r'[ \t]{20,}$')  # trailing only
STEG_BLANK_LINE_PATTERN = re.compile(r'^[ \t]{40,}$')  # all-whitespace line (40+ chars)

# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding."""
    detector: str          # detector name
    severity: str          # "critical", "high", "medium", "low", "info"
    line: int              # 0 if not line-specific
    description: str       # human-readable
    snippet: str           # the offending text (truncated)
    score_impact: int      # how many points this adds to the score

@dataclass
class ScanResult:
    path: str
    findings: list[Finding] = field(default_factory=list)
    ai_verdict: Optional[str] = None
    ai_findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        total = sum(f.score_impact for f in self.findings)
        total += sum(f.score_impact for f in self.ai_findings)
        return min(100, total)

    @property
    def verdict(self) -> str:
        if self.score >= 80:
            return "BLOCKED — dangerous, do not install"
        elif self.score >= 50:
            return "WARNING — suspicious, review carefully"
        elif self.score >= 20:
            return "CAUTION — minor concerns"
        else:
            return "SAFE — no significant threats detected"

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings + self.ai_findings if f.severity == "critical")


# ── Detectors ───────────────────────────────────────────────────────────────

class Detector:
    """Base class for detectors."""
    name: str = "base"
    description: str = ""

    def scan(self, content: str) -> list[Finding]:
        raise NotImplementedError


class UnicodeSpoofDetector(Detector):
    """Detect Unicode homoglyph characters used to spoof tool names."""

    name = "unicode-spoof"
    description = "Detects Unicode homoglyphs used to disguise tool names"

    def scan(self, content: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check each character in the line
            for j, ch in enumerate(line):
                if ch in SPOOF_TO_LATIN:
                    latin = SPOOF_TO_LATIN[ch]
                    # Get context around the character
                    start = max(0, j - 10)
                    end = min(len(line), j + 10)
                    ctx = line[start:end]

                    # Check if this appears in a tool-name context
                    # Replace the spoof char with its latin equivalent and check
                    normalized = "".join(
                        SPOOF_TO_LATIN.get(c, c) for c in ctx
                    )
                    is_tool_context = bool(TOOL_NAME_PATTERN.search(normalized))

                    findings.append(Finding(
                        detector=self.name,
                        severity="critical" if is_tool_context else "high",
                        line=i,
                        description=(
                            f"Unicode homoglyph spoofing: U+{ord(ch):04X} "
                            f"('{ch}') is a lookalike of Latin '{latin}'"
                            + (" — appears in tool-name context" if is_tool_context else "")
                        ),
                        snippet=ctx,
                        score_impact=25 if is_tool_context else 15,
                    ))

        return findings


class HiddenContentDetector(Detector):
    """Detect hidden/invisible content — zero-width chars, comments, stego."""

    name = "hidden-content"
    description = "Detects zero-width characters, hidden text, base64 payloads"

    def scan(self, content: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")
        seen = set()  # deduplicate: (line, category)

        # Zero-width characters
        for i, line in enumerate(lines, 1):
            zw_found = set()
            for ch in line:
                if ch in ZERO_WIDTH_CHARS:
                    zw_found.add(ch)
            if zw_found:
                key = (i, "zero-width")
                if key not in seen:
                    seen.add(key)
                    # List all ZW chars found on this line
                    chars_found = ", ".join(
                        f"U+{ord(c):04X} ({ZERO_WIDTH_CHARS[c]})"
                        for c in sorted(zw_found)
                    )
                    findings.append(Finding(
                        detector=self.name,
                        severity="critical",
                        line=i,
                        description=f"Zero-width characters: {chars_found} — can hide instructions from humans",
                        snippet=line[:120],
                        score_impact=30,
                    ))

            # Suspicious Unicode ranges (skip if we already flagged ZW chars on this line)
            key = (i, "suspicious-unicode")
            if key not in seen:
                for ch in line:
                    for rng, desc in SUSPICIOUS_UNICODE:
                        if ord(ch) in rng:
                            if ch in ZERO_WIDTH_CHARS:
                                continue  # already covered by ZW check above
                            seen.add(key)
                            findings.append(Finding(
                                detector=self.name,
                                severity="high",
                                line=i,
                                description=f"Suspicious Unicode: U+{ord(ch):04X} ({desc})",
                                snippet=line[:120],
                                score_impact=15,
                            ))
                            break

        # HTML comments (hidden in rendered markdown)
        # Track lines with HTML comments for layered obfuscation check
        html_comment_lines = set()
        for match in HTML_COMMENT_PATTERN.finditer(content):
            comment_text = match.group(0)
            inner = comment_text[4:-3]  # strip <!-- and -->
            line_num = content[:match.start()].count("\n") + 1

            if len(comment_text) > 20 and not comment_text.startswith("<!-- ---"):
                html_comment_lines.add(line_num)

                # Check if the comment body contains zero-width chars (layered obfuscation)
                has_zw = any(ch in ZERO_WIDTH_CHARS for ch in inner)
                comment_is_suspicious = any(
                    kw in inner.lower()
                    for kw in ["curl", "bash", "wget", "eval", "exec", "ssh", "key",
                               "token", "password", "exfil", "steal", "exploit",
                               "rm -rf", "nc -", "/dev/tcp", "base64"]
                )

                score = 10  # base score for hidden comment
                sev = "medium"
                desc = f"HTML comment ({len(comment_text)} chars) — content hidden from human readers but visible to agents"

                if has_zw or comment_is_suspicious:
                    score = 25
                    sev = "high"
                    desc = (
                        f"HTML comment ({len(comment_text)} chars) with "
                        + ("zero-width character obfuscation" if has_zw else "")
                        + (" and " if has_zw and comment_is_suspicious else "")
                        + ("suspicious keywords" if comment_is_suspicious else "")
                        + " — layered obfuscation attack"
                    )

                findings.append(Finding(
                    detector=self.name,
                    severity=sev,
                    line=line_num,
                    description=desc,
                    snippet=comment_text[:100],
                    score_impact=score,
                ))

        # Layered obfuscation check: ZW chars + HTML comment on same line
        for i in html_comment_lines:
            key = (i, "zero-width")
            if key in seen:
                # ZW chars found inside HTML comment — layered evasion
                findings.append(Finding(
                    detector=self.name,
                    severity="critical",
                    line=i,
                    description=(
                        "Layered obfuscation: zero-width characters inside HTML comment "
                        "— hides instructions from both humans AND pattern matchers. "
                        "This is a strong indicator of malicious intent."
                    ),
                    snippet="",
                    score_impact=25,
                ))

        # Base64 blobs (potential encoded payloads)
        for match in BASE64_PATTERN.finditer(content):
            blob = match.group(0)
            # Filter out common false positives (URLs, hashes)
            if not any(x in blob for x in ["http", "sha256", "sha512"]):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    line=line_num,
                    description=(
                        f"Base64-encoded blob ({len(blob)} chars) — "
                        "could be obfuscated malicious instructions"
                    ),
                    snippet=blob[:80] + "...",
                    score_impact=20,
                ))

        # Whitespace steganography — trailing whitespace only (structural alignment is fine)
        for i, line in enumerate(lines, 1):
            if STEG_WHITESPACE_PATTERN.search(line):
                findings.append(Finding(
                    detector=self.name,
                    severity="low",
                    line=i,
                    description=(
                        f"Trailing whitespace ({len(line.rstrip()) - len(line.rstrip().rstrip())} spaces) "
                        "— possible steganography"
                    ),
                    snippet=f"line ends with {len(line) - len(line.rstrip())} spaces",
                    score_impact=2,
                ))

        return findings


class MismatchDetector(Detector):
    """Detect when a skill's description doesn't match what its code does."""

    name = "description-mismatch"
    description = "Flags skills whose declared purpose doesn't match their code"

    # Patterns that suggest dangerous behavior regardless of description
    DANGEROUS_PATTERNS = [
        (re.compile(r'curl\s+.*\|\s*(?:bash|sh|python)', re.IGNORECASE),
         "curl-pipe-shell", "critical",
         "Piped curl to shell execution — remote code execution risk", 35),
        (re.compile(r'chmod\s+[+]x\s+/', re.IGNORECASE),
         "chmod-executable", "high",
         "Makes system files executable", 20),
        (re.compile(r'rm\s+-rf\s+/', re.IGNORECASE),
         "rm-rf-root", "critical",
         "Recursive delete from root — destructive", 50),
        (re.compile(r'sudo\s', re.IGNORECASE),
         "sudo-usage", "high",
         "Requests elevated privileges via sudo", 20),
        (re.compile(r'eval\s+["\x27].*\$', re.IGNORECASE),
         "eval-injection", "critical",
         "Dynamic eval with variable interpolation — injection risk", 35),
        (re.compile(r'__import__\s*\(\s*[\x27"].*os.*[\x27"]', re.IGNORECASE),
         "python-os-import", "high",
         "Dynamic import of os module", 15),
        (re.compile(r'subprocess\.(?:call|Popen|run|check_output)', re.IGNORECASE),
         "python-subprocess", "medium",
         "Spawns subprocesses — could execute arbitrary commands", 15),
        (re.compile(r'exec\s*\(', re.IGNORECASE),
         "python-exec", "critical",
         "Python exec() — arbitrary code execution", 35),
        (re.compile(r'\bwget\b.*\|\s*(?:bash|sh)\b', re.IGNORECASE),
         "wget-pipe-shell", "critical",
         "Download and pipe to shell — remote code execution", 35),
        (re.compile(r'>\s*/etc/(?:passwd|shadow|sudoers|hosts)', re.IGNORECASE),
         "system-file-write", "critical",
         "Writes to critical system files", 40),
        (re.compile(r'\.ssh/', re.IGNORECASE),
         "ssh-access", "high",
         "Accesses SSH directory — credential theft risk", 25),
        (re.compile(r'export\s+[A-Z_]*KEY\s*=', re.IGNORECASE),
         "env-key-export", "high",
         "Exports API keys to environment", 20),
    ]

    # Harmless/benign patterns that suggest a skill is what it says
    BENIGN_PATTERNS = [
        re.compile(r'^#+\s', re.MULTILINE),     # markdown headings
        re.compile(r'^\s*[-*]\s', re.MULTILINE), # list items
        re.compile(r'```', re.MULTILINE),         # code fences
        re.compile(r'\[.*?\]\(.*?\)'),           # markdown links
    ]

    def scan(self, content: str) -> list[Finding]:
        findings = []

        for pattern, pid, severity, desc, score in self.DANGEROUS_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    detector=self.name,
                    severity=severity,
                    line=line_num,
                    description=f"[{pid}] {desc}",
                    snippet=match.group(0)[:100],
                    score_impact=score,
                ))

        return findings


class FingerprintDetector(Detector):
    """Match against a library of known malicious skill fingerprints."""

    name = "fingerprint"
    description = "Compares code against known malware fingerprint library"

    def __init__(self, fingerprints_path: Path = FINGERPRINTS_PATH):
        self.fingerprints: list[dict] = []
        if fingerprints_path.exists():
            try:
                with open(fingerprints_path) as f:
                    data = json.load(f)
                    self.fingerprints = data.get("fingerprints", [])
            except (json.JSONDecodeError, OSError):
                pass

    def scan(self, content: str) -> list[Finding]:
        findings = []
        content_lower = content.lower()

        for fp in self.fingerprints:
            pattern = fp.get("pattern", "")
            if not pattern:
                continue
            try:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    findings.append(Finding(
                        detector=self.name,
                        severity=fp.get("severity", "high"),
                        line=0,
                        description=f"[{fp.get('id', 'unknown')}] {fp.get('description', 'Known malware pattern matched')}",
                        snippet=pattern[:100],
                        score_impact=fp.get("score_impact", 30),
                    ))
            except re.error:
                continue

        return findings


# ── Scanner engine ──────────────────────────────────────────────────────────

class SkillSpecter:
    """Main scanner engine — orchestrates all detectors."""

    def __init__(self):
        self.detectors: list[Detector] = [
            UnicodeSpoofDetector(),
            HiddenContentDetector(),
            MismatchDetector(),
            FingerprintDetector(),
        ]

    def find_skill_files(self, path: Path) -> list[Path]:
        """Find SKILL.md or .md files to scan."""
        if path.is_file():
            return [path]

        candidates = []
        # Look for SKILL.md first
        skill_md = path / "SKILL.md"
        if skill_md.exists():
            candidates.append(skill_md)

        # Also scan any .md files
        for md_file in sorted(path.glob("*.md")):
            if md_file not in candidates:
                candidates.append(md_file)

        # Also scan .py, .sh, .js files
        for ext in ["*.py", "*.sh", "*.js", "*.ts"]:
            candidates.extend(sorted(path.glob(ext)))

        return candidates

    def scan_file(self, filepath: Path) -> ScanResult:
        """Run all detectors against a single file."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return ScanResult(
                path=str(filepath),
                findings=[Finding(
                    detector="scanner", severity="info", line=0,
                    description=f"Could not read file: {e}", snippet="",
                    score_impact=0,
                )]
            )

        result = ScanResult(path=str(filepath))
        for detector in self.detectors:
            try:
                result.findings.extend(detector.scan(content))
            except Exception as e:
                result.findings.append(Finding(
                    detector=detector.name, severity="info", line=0,
                    description=f"Detector error: {e}", snippet="",
                    score_impact=0,
                ))

        return result

    def scan(self, path: Path) -> list[ScanResult]:
        """Scan a file or directory. Returns results per file."""
        files = self.find_skill_files(path)
        if not files:
            print(f"No scannable files found in {path}", file=sys.stderr)
            return []

        results = []
        for f in files:
            results.append(self.scan_file(f))
        return results

    def ai_scan(self, path: Path) -> list[ScanResult]:
        """Run pattern scan first, then AI deep scan on flagged files."""
        results = self.scan(path)

        # Only AI-scan files with findings above threshold
        for result in results:
            if result.score >= 20:
                self._run_ai_review(result)

        return results

    def _run_ai_review(self, result: ScanResult) -> None:
        """Invoke Claude Code headless for AI security review."""

        # Build a compact summary of findings for Claude
        finding_summary = "\n".join(
            f"  - [{f.severity}] [{f.detector}] L{f.line}: {f.description}"
            for f in result.findings[:10]  # Cap at 10 to keep prompt tight
        )

        prompt = f"""You are a security auditor reviewing a Claude Code skill file.

FILE: {result.path}

PATTERN SCAN FINDINGS:
{finding_summary if finding_summary else 'No pattern findings'}

CONTEXT: You are reviewing a skill that will be installed into Claude Code.
Skills are markdown files with instructions that an AI agent follows.

TASK:
1. For each finding above, determine if it's a REAL threat or FALSE POSITIVE
2. Look for additional threats the pattern scanner may have missed
3. Rate overall risk: SAFE / SUSPICIOUS / DANGEROUS
4. If DANGEROUS, explain exactly what the attack would do

Respond in JSON:
{{
  "verdict": "SAFE|SUSPICIOUS|DANGEROUS",
  "findings": [
    {{
      "id": "<finding-id>",
      "verdict": "real|false_positive",
      "reasoning": "..."
    }}
  ],
  "additional_threats": ["..."],
  "overall_risk": "<explanation>"
}}"""

        try:
            proc = subprocess.run(
                ["claude", "-p", prompt],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING": "1"},
            )
            if proc.returncode == 0 and proc.stdout.strip():
                # Try to extract JSON from Claude's response
                json_match = re.search(r'\{.*\}', proc.stdout, re.DOTALL)
                if json_match:
                    ai_data = json.loads(json_match.group(0))
                    result.ai_verdict = ai_data.get("verdict", "UNKNOWN")

                    # Track which pattern finding indices are false positives
                    false_positive_indices = set()
                    for af in ai_data.get("findings", []):
                        # Parse "id" which may be an index into result.findings
                        finding_id = af.get("id", "")
                        if af.get("verdict") == "real":
                            result.ai_findings.append(Finding(
                                detector="ai-review",
                                severity="high",
                                line=0,
                                description=f"AI confirmed: {af.get('reasoning', '')}",
                                snippet="",
                                score_impact=20,
                            ))
                        elif af.get("verdict") == "false_positive":
                            # Try to match the finding by index
                            try:
                                idx = int(finding_id) if finding_id.isdigit() else -1
                                if 0 <= idx < len(result.findings):
                                    false_positive_indices.add(idx)
                            except (ValueError, TypeError):
                                pass

                    # When overall verdict is SAFE, drop all pattern finding scores
                    if result.ai_verdict == "SAFE":
                        for f in result.findings:
                            f.score_impact = 0
                    else:
                        # Only drop specific false positives
                        for idx in sorted(false_positive_indices, reverse=True):
                            if idx < len(result.findings):
                                result.findings[idx].score_impact = 0

                    for threat in ai_data.get("additional_threats", []):
                        result.ai_findings.append(Finding(
                            detector="ai-review",
                            severity="high",
                            line=0,
                            description=f"AI discovered additional threat: {threat}",
                            snippet="",
                            score_impact=15,
                        ))
            else:
                result.ai_verdict = f"AI_SCAN_FAILED: {proc.stderr[:200]}"

        except FileNotFoundError:
            result.ai_verdict = "AI_SCAN_FAILED: claude CLI not found in PATH"
        except subprocess.TimeoutExpired:
            result.ai_verdict = "AI_SCAN_FAILED: timeout after 120s"
        except json.JSONDecodeError:
            result.ai_verdict = "AI_SCAN_FAILED: could not parse Claude response"
        except Exception as e:
            result.ai_verdict = f"AI_SCAN_FAILED: {e}"

    def auto_fix(self, path: Path) -> list[ScanResult]:
        """Scan → AI review → fix → verify loop."""
        results = self.ai_scan(path)

        for result in results:
            if result.score < 50:
                continue

            # Build fix prompt
            finding_text = "\n".join(
                f"  - [{f.severity}] {f.description}"
                for f in (result.findings + result.ai_findings)
                if f.severity in ("critical", "high")
            )

            if not finding_text:
                continue

            fix_prompt = f"""You are a security fixer. A Claude Code skill has these security issues:

{finding_text}

TASK: Fix ALL of these issues by editing the file. For each issue:
- Remove invisible/hidden characters
- Replace Unicode homoglyphs with their proper Latin equivalents
- Remove or comment out dangerous code patterns
- Add clear warnings about what the skill does

After fixing, verify the skill still works as intended. Explain each fix.

IMPORTANT: Only fix actual security issues. Do NOT modify benign content."""

            try:
                subprocess.run(
                    ["claude", "-p", fix_prompt,
                     "--add-dir", str(path.parent)],
                    timeout=180,
                    env={**os.environ, "CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING": "1"},
                )
            except Exception:
                pass

        # Re-scan to verify fixes
        return self.ai_scan(path)


# ── Output formatters ───────────────────────────────────────────────────────

COLORS = {
    "critical": "\033[1;31m",  # bold red
    "high":     "\033[31m",    # red
    "medium":   "\033[33m",    # yellow
    "low":      "\033[36m",    # cyan
    "info":     "\033[90m",    # grey
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "green":    "\033[32m",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


def format_terminal(results: list[ScanResult]) -> str:
    """Pretty-print scan results for terminal output."""
    lines = []
    total_score = max((r.score for r in results), default=0)
    total_findings = sum(len(r.findings) + len(r.ai_findings) for r in results)

    lines.append("")
    lines.append(f"{COLORS['bold']}╔══════════════════════════════════════════╗{COLORS['reset']}")
    lines.append(f"{COLORS['bold']}║        Skill Specter — Scan Report       ║{COLORS['reset']}")
    lines.append(f"{COLORS['bold']}╚══════════════════════════════════════════╝{COLORS['reset']}")
    lines.append("")

    for result in results:
        fname = Path(result.path).name
        lines.append(f"{COLORS['bold']}── {fname} ──{COLORS['reset']}")

        # Score bar
        score = result.score
        if score >= 80:
            color = COLORS["critical"]
        elif score >= 50:
            color = COLORS["high"]
        elif score >= 20:
            color = COLORS["medium"]
        else:
            color = COLORS["green"]

        bar_len = min(40, score)
        bar_empty = 40 - bar_len
        score_bar = "█" * (bar_len // 2) + "░" * (bar_empty // 2)
        lines.append(f"  Score: {color}{score}/100{COLORS['reset']}  [{score_bar}]")
        lines.append(f"  Verdict: {color}{result.verdict}{COLORS['reset']}")
        lines.append("")

        # Group findings by severity
        all_findings = result.findings + result.ai_findings
        all_findings.sort(key=lambda f: {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }.get(f.severity, 5))

        if all_findings:
            for f in all_findings:
                icon = SEVERITY_ICONS.get(f.severity, "  ")
                sev = f"{COLORS.get(f.severity, '')}{f.severity.upper():8s}{COLORS['reset']}"
                det = f"{COLORS['info']}[{f.detector}]{COLORS['reset']}"
                loc = f"L{f.line:04d}" if f.line else "     "
                lines.append(f"  {icon} {sev} {det} {loc}  {f.description}")
                if f.snippet:
                    snip = f.snippet[:80].replace("\n", "\\n")
                    lines.append(f"     {COLORS['info']}snippet: {snip}...{COLORS['reset']}")
            lines.append("")

        # AI verdict if available
        if result.ai_verdict:
            lines.append(f"  {COLORS['bold']}AI Review:{COLORS['reset']} {result.ai_verdict}")
            lines.append("")

    # Summary footer
    lines.append(f"{COLORS['bold']}──────────────────────────────────────────{COLORS['reset']}")
    lines.append(f"  Files scanned: {len(results)}")
    lines.append(f"  Total findings: {total_findings}")
    lines.append(f"  Overall score: {total_score}/100")
    lines.append(f"  Critical issues: {sum(r.critical_count for r in results)}")
    lines.append("")

    return "\n".join(lines)


def format_json(results: list[ScanResult]) -> str:
    """JSON output for automation."""
    output = []
    for r in results:
        output.append({
            "path": r.path,
            "score": r.score,
            "verdict": r.verdict,
            "findings": [
                {
                    "detector": f.detector,
                    "severity": f.severity,
                    "line": f.line,
                    "description": f.description,
                    "snippet": f.snippet,
                    "score_impact": f.score_impact,
                }
                for f in r.findings + r.ai_findings
            ],
            "ai_verdict": r.ai_verdict,
        })
    return json.dumps(output, indent=2, ensure_ascii=False)


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Skill Specter — security scanner for Claude Code skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  skill-specter scan ~/.claude/skills/my-skill/
  skill-specter scan --ai /path/to/SKILL.md
  skill-specter fix ~/.claude/skills/suspicious-skill/
  skill-specter score --json /path/to/skill/
        """,
    )

    sub = parser.add_subparsers(dest="command", help="Command")

    # scan
    scan_parser = sub.add_parser("scan", help="Scan a skill file or directory")
    scan_parser.add_argument("path", help="Path to skill directory or SKILL.md")
    scan_parser.add_argument("--ai", action="store_true", help="Enable AI deep scan (Claude headless)")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--fix", action="store_true", help="Auto-fix issues after scan")

    # fix
    fix_parser = sub.add_parser("fix", help="Scan, fix, and verify a skill")
    fix_parser.add_argument("path", help="Path to skill directory or SKILL.md")
    fix_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # score
    score_parser = sub.add_parser("score", help="Quick security score only")
    score_parser.add_argument("path", help="Path to skill")
    score_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    specter = SkillSpecter()
    target = Path(args.path).expanduser().resolve()

    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    if args.command == "scan":
        if args.ai or args.fix:
            results = specter.ai_scan(target)
        else:
            results = specter.scan(target)

        if args.json:
            print(format_json(results))
        else:
            print(format_terminal(results))

    elif args.command == "fix":
        print("Running scan → AI review → fix → verify loop...")
        results = specter.auto_fix(target)

        if args.json:
            print(format_json(results))
        else:
            print(format_terminal(results))

    elif args.command == "score":
        results = specter.scan(target)
        if args.json:
            print(format_json(results))
        else:
            score = max((r.score for r in results), default=0)
            print(f"{score}")


if __name__ == "__main__":
    main()
