"""
Password Strength Analyzer - Core Engine
Analyzes passwords using entropy, NIST SP 800-63B guidelines,
pattern detection, and HaveIBeenPwned API integration.
"""

import re
import math
import string
import hashlib
import httpx
from dataclasses import dataclass, field
from enum import Enum


class StrengthLevel(Enum):
    VERY_WEAK  = ("Very Weak",  "🔴")
    WEAK       = ("Weak",       "🟠")
    FAIR       = ("Fair",       "🟡")
    STRONG     = ("Strong",     "🟢")
    VERY_STRONG= ("Very Strong","💪")

    def __init__(self, label, icon):
        self.label = label
        self.icon  = icon


@dataclass
class AnalysisResult:
    password:       str
    score:          int             = 0   # 0–100
    strength:       StrengthLevel   = StrengthLevel.VERY_WEAK
    entropy_bits:   float           = 0.0
    charset_size:   int             = 0
    issues:         list[str]       = field(default_factory=list)
    suggestions:    list[str]       = field(default_factory=list)
    patterns_found: list[str]       = field(default_factory=list)
    pwned_count:    int             = -1   # -1 = not checked
    time_to_crack:  str             = ""

    def is_pwned(self) -> bool:
        return self.pwned_count > 0


# ── Common weak password patterns ─────────────────────────────────────────────
PATTERNS = {
    "keyboard_walk":  re.compile(r"(qwerty|asdf|zxcv|qazwsx|1qaz|2wsx)", re.I),
    "sequential_num": re.compile(r"(0123|1234|2345|3456|4567|5678|6789|7890)"),
    "sequential_abc": re.compile(r"(abcd|bcde|cdef|defg|efgh|fghi|ghij)", re.I),
    "repeated_chars": re.compile(r"(.)\1{2,}"),
    "dates":          re.compile(r"\b(19|20)\d{2}(0[1-9]|1[0-2])?\b"),
    "phone_like":     re.compile(r"\d{10,}"),
    "common_words":   re.compile(
        r"(password|passwd|pass|secret|admin|login|welcome|"
        r"monkey|dragon|master|sunshine|shadow|football|baseball)", re.I),
}

CRACK_TIMES = [
    (1e3,  "less than a second (online attack)"),
    (1e6,  "seconds (offline, fast hash)"),
    (1e9,  "minutes"),
    (1e12, "hours"),
    (1e15, "days"),
    (1e18, "months"),
    (1e21, "years"),
    (float("inf"), "centuries (effectively uncrackable)"),
]


def _charset_size(password: str) -> int:
    """Return the size of the character set used."""
    size = 0
    if any(c in string.ascii_lowercase for c in password): size += 26
    if any(c in string.ascii_uppercase for c in password): size += 26
    if any(c in string.digits          for c in password): size += 10
    if any(c in string.punctuation     for c in password): size += 32
    return size or 1


def _entropy(password: str, charset: int) -> float:
    """Shannon entropy: log2(charset^length)."""
    return len(password) * math.log2(charset)


def _crack_time(entropy: float) -> str:
    """Estimate crack time at 1 trillion guesses/sec (modern GPU cluster)."""
    combinations = 2 ** entropy
    guesses_per_sec = 1e12
    seconds = combinations / guesses_per_sec / 2   # average case
    for threshold, label in CRACK_TIMES:
        if seconds < threshold:
            return label
    return "centuries"


def _detect_patterns(password: str) -> list[str]:
    found = []
    for name, pattern in PATTERNS.items():
        if pattern.search(password):
            found.append(name.replace("_", " "))
    return found


def check_haveibeenpwned(password: str) -> int:
    """
    Uses the k-Anonymity model — only the first 5 chars of the SHA-1
    hash are sent to the API. The password itself never leaves your machine.
    Returns the breach count (0 = safe, -1 = API error).
    """
    sha1  = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"Add-Padding": "true"},
        )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return -1


def analyze(password: str, check_pwned: bool = True) -> AnalysisResult:
    """Full analysis pipeline."""
    result = AnalysisResult(password=password)

    # ── 1. Charset & Entropy ──────────────────────────────────────────────────
    result.charset_size = _charset_size(password)
    result.entropy_bits = _entropy(password, result.charset_size)
    result.time_to_crack = _crack_time(result.entropy_bits)

    # ── 2. Base score from entropy (0–60 pts) ────────────────────────────────
    score = min(60, int(result.entropy_bits * 1.5))

    # ── 3. NIST & length rules ────────────────────────────────────────────────
    length = len(password)
    if length < 8:
        result.issues.append("Too short — minimum 8 characters (NIST SP 800-63B)")
        result.suggestions.append("Use at least 8 characters; 16+ is recommended.")
        score -= 20
    elif length < 12:
        result.suggestions.append("Consider a longer password (12+ chars) for better security.")
        score += 5
    elif length >= 16:
        score += 10
    elif length >= 20:
        score += 15

    # ── 4. Charset diversity bonuses ─────────────────────────────────────────
    has_lower  = any(c in string.ascii_lowercase for c in password)
    has_upper  = any(c in string.ascii_uppercase for c in password)
    has_digit  = any(c in string.digits          for c in password)
    has_symbol = any(c in string.punctuation     for c in password)

    diversity = sum([has_lower, has_upper, has_digit, has_symbol])
    score += (diversity - 1) * 5

    if not has_upper:
        result.suggestions.append("Add uppercase letters to increase entropy.")
    if not has_digit:
        result.suggestions.append("Include numbers for extra complexity.")
    if not has_symbol:
        result.suggestions.append("Special characters (!@#$...) significantly boost strength.")

    # ── 5. Pattern penalties ──────────────────────────────────────────────────
    result.patterns_found = _detect_patterns(password)
    for pattern in result.patterns_found:
        result.issues.append(f"Detected weak pattern: '{pattern}'")
        score -= 10

    if result.patterns_found:
        result.suggestions.append(
            "Avoid keyboard walks, sequential numbers, and dictionary words."
        )

    # ── 6. HaveIBeenPwned check ───────────────────────────────────────────────
    if check_pwned:
        result.pwned_count = check_haveibeenpwned(password)
        if result.pwned_count > 0:
            result.issues.append(
                f"Found in {result.pwned_count:,} data breaches! Change immediately."
            )
            result.suggestions.append(
                "This password is publicly known. Choose a completely different one."
            )
            score -= 40
        elif result.pwned_count == 0:
            score += 10   # bonus for not appearing in breach lists

    # ── 7. Normalize score & assign level ────────────────────────────────────
    result.score = max(0, min(100, score))

    if result.score < 20:   result.strength = StrengthLevel.VERY_WEAK
    elif result.score < 40: result.strength = StrengthLevel.WEAK
    elif result.score < 60: result.strength = StrengthLevel.FAIR
    elif result.score < 80: result.strength = StrengthLevel.STRONG
    else:                   result.strength = StrengthLevel.VERY_STRONG

    return result
