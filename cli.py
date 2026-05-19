#!/usr/bin/env python3
"""
Password Strength Analyzer — CLI
Usage:
    python cli.py                        # interactive mode
    python cli.py -p "MyP@ssw0rd!"      # single password
    python cli.py -f passwords.txt       # batch file
    python cli.py -p "secret" --no-pwned # skip HIBP check
    python cli.py --generate 20          # suggest a strong password
"""

import argparse
import sys
import os
import secrets
import string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.analyzer import analyze, AnalysisResult, StrengthLevel

# ── ANSI colour helpers ────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
WHITE  = "\033[97m"

SCORE_COLORS = {
    StrengthLevel.VERY_WEAK:   RED,
    StrengthLevel.WEAK:        RED,
    StrengthLevel.FAIR:        YELLOW,
    StrengthLevel.STRONG:      GREEN,
    StrengthLevel.VERY_STRONG: GREEN,
}


def _bar(score: int, width: int = 30) -> str:
    filled  = int(score / 100 * width)
    color   = RED if score < 40 else YELLOW if score < 60 else GREEN
    bar     = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{RESET}"


def _mask(password: str) -> str:
    """Show first and last char, mask the middle."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def print_result(result: AnalysisResult, show_password: bool = False) -> None:
    pw_display = result.password if show_password else _mask(result.password)

    print(f"\n{BOLD}{'─'*52}{RESET}")
    print(f"  {BOLD}Password:{RESET}  {CYAN}{pw_display}{RESET}  "
          f"({GREY}length: {len(result.password)}{RESET})")
    print(f"{'─'*52}")

    # Score bar
    color = SCORE_COLORS[result.strength]
    print(f"  {BOLD}Score:{RESET}     {_bar(result.score)}  "
          f"{color}{BOLD}{result.score}/100{RESET}")
    print(f"  {BOLD}Strength:{RESET}  "
          f"{color}{result.strength.icon}  {result.strength.label}{RESET}")

    # Entropy
    print(f"\n  {BOLD}Entropy:{RESET}   {result.entropy_bits:.1f} bits  "
          f"(charset: {result.charset_size} chars)")
    print(f"  {BOLD}Crack est:{RESET} {GREY}{result.time_to_crack}{RESET}")

    # HIBP
    if result.pwned_count == -1:
        print(f"  {BOLD}HIBP:{RESET}      {GREY}(check skipped){RESET}")
    elif result.pwned_count == 0:
        print(f"  {BOLD}HIBP:{RESET}      {GREEN}✓ Not found in any known breach{RESET}")
    else:
        print(f"  {BOLD}HIBP:{RESET}      {RED}✗ Found in {result.pwned_count:,} breaches!{RESET}")

    # Patterns
    if result.patterns_found:
        pats = ", ".join(result.patterns_found)
        print(f"\n  {BOLD}Patterns:{RESET}  {YELLOW}⚠  {pats}{RESET}")

    # Issues
    if result.issues:
        print(f"\n  {BOLD}{RED}Issues:{RESET}")
        for issue in result.issues:
            print(f"    {RED}•  {issue}{RESET}")

    # Suggestions
    if result.suggestions:
        print(f"\n  {BOLD}{CYAN}Suggestions:{RESET}")
        for tip in result.suggestions:
            print(f"    {CYAN}→  {tip}{RESET}")

    print(f"{BOLD}{'─'*52}{RESET}\n")


def generate_password(length: int = 20) -> str:
    """Generate a cryptographically secure, policy-compliant password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure all character classes are present
        if (any(c.islower() for c in pw) and
                any(c.isupper() for c in pw) and
                any(c.isdigit() for c in pw) and
                any(c in string.punctuation for c in pw)):
            return pw


def batch_analyze(filepath: str, check_pwned: bool) -> None:
    """Analyze passwords from a file, one per line."""
    try:
        with open(filepath) as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}Error: File '{filepath}' not found.{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}Analyzing {len(passwords)} passwords from '{filepath}'...{RESET}\n")

    summary = {lvl: 0 for lvl in StrengthLevel}
    for pw in passwords:
        result = analyze(pw, check_pwned=check_pwned)
        summary[result.strength] += 1
        print_result(result)

    # Summary table
    print(f"\n{BOLD}{'─'*30}{RESET}")
    print(f"{BOLD}  BATCH SUMMARY{RESET}")
    print(f"{'─'*30}")
    for lvl, count in summary.items():
        if count:
            color = SCORE_COLORS[lvl]
            print(f"  {color}{lvl.icon}  {lvl.label:<12}{RESET} {count}")
    print(f"{'─'*30}\n")


def interactive_mode(check_pwned: bool) -> None:
    print(f"\n{BOLD}{CYAN}Password Strength Analyzer — Interactive Mode{RESET}")
    print(f"{GREY}Type a password to analyze it. Press Ctrl+C to quit.{RESET}\n")

    while True:
        try:
            pw = input(f"{BOLD}Enter password:{RESET} ")
            if not pw:
                continue
            result = analyze(pw, check_pwned=check_pwned)
            print_result(result, show_password=True)
        except KeyboardInterrupt:
            print(f"\n{GREY}Goodbye!{RESET}\n")
            break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze password strength using entropy, patterns, and HIBP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--password",  help="Password to analyze")
    group.add_argument("-f", "--file",      help="File with one password per line")
    group.add_argument("-g", "--generate",  type=int, metavar="LENGTH",
                       help="Generate a secure password of given length")
    parser.add_argument("--no-pwned", action="store_true",
                        help="Skip HaveIBeenPwned API check (faster, offline)")
    parser.add_argument("--show",     action="store_true",
                        help="Show password in plain text (default: masked)")
    args = parser.parse_args()

    check_pwned = not args.no_pwned

    if args.generate:
        pw = generate_password(args.generate)
        print(f"\n{BOLD}Generated password ({args.generate} chars):{RESET}")
        print(f"  {GREEN}{pw}{RESET}")
        result = analyze(pw, check_pwned=check_pwned)
        print_result(result, show_password=True)

    elif args.password:
        result = analyze(args.password, check_pwned=check_pwned)
        print_result(result, show_password=args.show)

    elif args.file:
        batch_analyze(args.file, check_pwned)

    else:
        interactive_mode(check_pwned)


if __name__ == "__main__":
    main()
