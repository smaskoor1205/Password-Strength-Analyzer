"""
Tests for the Password Strength Analyzer.
Run with: pytest tests/ -v
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.analyzer import (
    analyze, _charset_size, _entropy, _detect_patterns,
    StrengthLevel, check_haveibeenpwned
)


# ── Charset size ───────────────────────────────────────────────────────────────
class TestCharsetSize:
    def test_lowercase_only(self):
        assert _charset_size("abcdef") == 26

    def test_lowercase_and_digits(self):
        assert _charset_size("abc123") == 36

    def test_all_classes(self):
        assert _charset_size("aA1!") == 94

    def test_empty_string(self):
        assert _charset_size("") == 1  # guard against log2(0)


# ── Entropy ───────────────────────────────────────────────────────────────────
class TestEntropy:
    def test_increases_with_length(self):
        e8  = _entropy("aaaaaaaa", 26)
        e16 = _entropy("aaaaaaaaaaaaaaaa", 26)
        assert e16 == pytest.approx(2 * e8)

    def test_increases_with_charset(self):
        small = _entropy("test", 26)
        large = _entropy("test", 94)
        assert large > small


# ── Pattern detection ─────────────────────────────────────────────────────────
class TestPatternDetection:
    def test_keyboard_walk(self):
        assert "keyboard walk" in _detect_patterns("qwerty123")

    def test_sequential_numbers(self):
        assert "sequential num" in _detect_patterns("pass1234")

    def test_common_word(self):
        assert "common words" in _detect_patterns("mypassword1")

    def test_repeated_chars(self):
        assert "repeated chars" in _detect_patterns("aaabbb")

    def test_clean_password(self):
        assert _detect_patterns("Tr0ub4dor&3") == []


# ── Full analysis ─────────────────────────────────────────────────────────────
class TestAnalyze:
    def test_very_weak_short(self):
        result = analyze("abc", check_pwned=False)
        assert result.strength in (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK)
        assert result.score < 40

    def test_strong_complex(self):
        result = analyze("Tr0ub4dor&3!XyZ#", check_pwned=False)
        assert result.strength in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)
        assert result.score >= 60

    def test_common_password_penalized(self):
        result = analyze("password123", check_pwned=False)
        assert result.score < 50
        assert any("pattern" in i.lower() for i in result.issues)

    def test_score_in_range(self):
        for pw in ["a", "password", "Tr0ub4dor&3!XyZ#99!!", "💀"]:
            r = analyze(pw, check_pwned=False)
            assert 0 <= r.score <= 100

    def test_entropy_reported(self):
        result = analyze("SomePassword!", check_pwned=False)
        assert result.entropy_bits > 0

    def test_suggestions_given_for_weak(self):
        result = analyze("abc", check_pwned=False)
        assert len(result.suggestions) > 0

    def test_pwned_skip(self):
        result = analyze("SomePassword!", check_pwned=False)
        assert result.pwned_count == -1

    def test_pwned_known_bad(self):
        # "password" is definitely in HIBP — uses real API
        result = analyze("password", check_pwned=True)
        if result.pwned_count != -1:   # skip if offline
            assert result.pwned_count > 0
            assert result.is_pwned()


# ── Generator (from cli) ──────────────────────────────────────────────────────
class TestGenerator:
    def test_generated_password_is_strong(self):
        from cli import generate_password
        import string
        for _ in range(10):
            pw = generate_password(20)
            assert len(pw) == 20
            assert any(c.islower()            for c in pw)
            assert any(c.isupper()            for c in pw)
            assert any(c.isdigit()            for c in pw)
            assert any(c in string.punctuation for c in pw)
