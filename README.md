# 🔐 Password Strength Analyzer

A cybersecurity tool that evaluates password strength using **entropy analysis**, **NIST SP 800-63B guidelines**, **pattern detection**, and the **HaveIBeenPwned k-Anonymity API** — all from the command line.

---

## Features

- **Entropy-based scoring** — measures true randomness, not just checkbox rules
- **NIST SP 800-63B compliance** — length, complexity, and common-password checks
- **Pattern detection** — catches keyboard walks, sequential numbers, dictionary words, repeated chars
- **HaveIBeenPwned API** — checks if the password appears in known data breaches (k-Anonymity: your password never leaves your machine)
- **Crack time estimation** — estimates brute-force time at 1 trillion guesses/sec
- **Secure password generator** — cryptographically random, policy-compliant passwords
- **Batch mode** — analyze a list of passwords from a file
- **Interactive mode** — live feedback as you type

---

## Project Structure

```
password-strength-analyzer/
├── src/
│   ├── __init__.py
│   └── analyzer.py        # Core engine: entropy, patterns, HIBP
├── tests/
│   └── test_analyzer.py   # pytest test suite
├── docs/
│   └── sample_passwords.txt
├── cli.py                 # CLI entry point
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/yourusername/password-strength-analyzer.git
cd password-strength-analyzer
pip install -r requirements.txt
```

---

## Usage

### Interactive mode (type passwords, get instant feedback)
```bash
python cli.py
```

### Analyze a single password
```bash
python cli.py -p "MyP@ssw0rd!"
```

### Analyze without HIBP check (offline mode)
```bash
python cli.py -p "MyP@ssw0rd!" --no-pwned
```

### Batch analyze from file
```bash
python cli.py -f docs/sample_passwords.txt
```

### Generate a secure password
```bash
python cli.py --generate 20
```

---

## Example Output

```
────────────────────────────────────────────────────
  Password:  p*******3  (length: 9)
────────────────────────────────────────────────────
  Score:     ████░░░░░░░░░░░░░░░░░░░░░░░░░░  22/100
  Strength:  🔴  Very Weak

  Entropy:   42.5 bits  (charset: 36 chars)
  Crack est: minutes
  HIBP:      ✗ Found in 9,834,610 breaches!

  Patterns:  common words

  Issues:
    •  Found in 9,834,610 data breaches! Change immediately.
    •  Detected weak pattern: 'common words'

  Suggestions:
    →  This password is publicly known. Choose a completely different one.
    →  Add uppercase letters to increase entropy.
    →  Special characters (!@#$...) significantly boost strength.
────────────────────────────────────────────────────
```

---

## How It Works

### Entropy Calculation
```
entropy = length × log₂(charset_size)
```
A password using all 94 printable ASCII characters gets a charset size of 94. Longer passwords with larger charsets = exponentially harder to crack.

### HaveIBeenPwned (k-Anonymity)
1. SHA-1 hash the password locally
2. Send only the **first 5 characters** of the hash to the HIBP API
3. HIBP returns all hashes matching that prefix
4. Compare the rest locally — **the full password never leaves your machine**

### Scoring Breakdown
| Component              | Max Points |
|------------------------|-----------|
| Entropy (bits)         | 60        |
| Length bonus (16+)     | 15        |
| Charset diversity      | 15        |
| Not in HIBP            | 10        |
| Pattern penalty        | -10 each  |
| Breach penalty         | -40       |

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Skills Demonstrated

- Python (dataclasses, enums, argparse, secrets, hashlib)
- REST API integration with k-Anonymity privacy model
- Cryptographic concepts (entropy, SHA-1, charset analysis)
- NIST cybersecurity guidelines
- CLI tool design with ANSI formatting
- pytest unit testing

---


