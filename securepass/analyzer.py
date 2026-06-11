# takes all Phase 2 checks and produces a final score + report
from dataclasses import dataclass, field
from typing import List

from securepass.utils import (
    calculate_entropy,
    has_uppercase,
    has_lowercase,
    has_digit,
    has_special,
    is_long_enough,
    has_sequential_chars,
    has_repeated_chars,
    detect_leet_speak,
    has_common_suffix,
    has_common_prefix,
)
from securepass.wordlist import COMMON_PASSWORDS
from securepass.checker import check_pwned


# ────────────────────────────────────────────────────────────
#  PASSWORD REPORT
#  A dataclass is like a structured container for results.
#  Instead of passing 15 separate variables around, we bundle
#  everything into one clean object.
# ────────────────────────────────────────────────────────────

@dataclass
class PasswordReport:
    """Holds the complete analysis result for one password."""

    # Input
    password: str = ""

    # Score and label
    score: int = 0                      # 0 to 100
    strength_label: str = ""            # "Very Weak" → "Very Strong"
    strength_color: str = ""            # used by the web UI for styling

    # Stats
    entropy: float = 0.0                # bits of randomness
    length: int = 0

    # Wordlist check
    is_common: bool = False             # found in top 100 common passwords

    # Breach check
    breach_count: int = 0              # times found in real breaches
    breach_check_failed: bool = False  # True if API was unreachable

    # Checks that ADD to score
    check_uppercase: bool = False
    check_lowercase: bool = False
    check_digit: bool = False
    check_special: bool = False
    check_length: bool = False

    # Patterns that SUBTRACT from score
    warn_sequential: bool = False
    warn_repeated: bool = False
    warn_leet: List[str] = field(default_factory=list)
    warn_suffix: bool = False
    warn_prefix: bool = False

    # Suggestions shown to the user
    suggestions: List[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────
#  SCORING WEIGHTS
#  Every property either adds or subtracts points.
#  Based loosely on NIST SP 800-63B guidelines — the real
#  US government standard for password security.
# ────────────────────────────────────────────────────────────

WEIGHTS = {
    # Positive contributions (max possible = 75 pts from these)
    'uppercase':      10,
    'lowercase':      10,
    'digit':          10,
    'special':        15,
    'entropy_high':   15,   # entropy > 60 bits
    'entropy_mid':     8,   # entropy 45–60 bits

    # Penalties
    'common':        -50,   # known bad password → severe
    'breached':      -40,   # found in real breach data → severe
    'sequential':    -10,
    'repeated':      -10,
    'leet':           -5,
    'bad_suffix':     -5,
    'bad_prefix':     -5,
}


# ────────────────────────────────────────────────────────────
#  MAIN ANALYSIS FUNCTION
#  This is the single function the web server will call.
#  It returns a fully populated PasswordReport.
# ────────────────────────────────────────────────────────────

def analyze_password(password: str, check_breach: bool = True) -> PasswordReport:
    """
    Analyzes a password across all security dimensions.

    Parameters:
        password     (str)  : the password to check
        check_breach (bool) : whether to call HaveIBeenPwned API
                              set False for tests or offline use

    Returns:
        PasswordReport: complete analysis with score and suggestions
    """

    report = PasswordReport(password=password)
    report.length = len(password)

    # ── Step 1: Run every individual check ───────────────────────────────
    report.entropy          = calculate_entropy(password)
    report.check_uppercase  = has_uppercase(password)
    report.check_lowercase  = has_lowercase(password)
    report.check_digit      = has_digit(password)
    report.check_special    = has_special(password)
    report.check_length     = is_long_enough(password)
    report.warn_sequential  = has_sequential_chars(password)
    report.warn_repeated    = has_repeated_chars(password)
    report.warn_leet        = detect_leet_speak(password)
    report.warn_suffix      = has_common_suffix(password)
    report.warn_prefix      = has_common_prefix(password)
    report.is_common        = password.lower() in COMMON_PASSWORDS

    # ── Step 2: Breach check (requires internet) ──────────────────────────
    if check_breach:
        result = check_pwned(password)
        if result == -1:
            report.breach_check_failed = True
        else:
            report.breach_count = result

    # ── Step 3: Calculate score ───────────────────────────────────────────

    score = 0

    # Length contributes up to 20 points, proportional
    # 6 chars  →  7 pts
    # 12 chars → 15 pts
    # 20 chars → 20 pts (capped)
    length_score = min(20, int((report.length / 20) * 20))
    score += length_score

    # Character variety
    if report.check_uppercase: score += WEIGHTS['uppercase']
    if report.check_lowercase: score += WEIGHTS['lowercase']
    if report.check_digit:     score += WEIGHTS['digit']
    if report.check_special:   score += WEIGHTS['special']

    # Entropy bonus
    if report.entropy > 60:
        score += WEIGHTS['entropy_high']
    elif report.entropy > 45:
        score += WEIGHTS['entropy_mid']

    # Penalties
    if report.is_common:          score += WEIGHTS['common']
    if report.breach_count > 0:   score += WEIGHTS['breached']
    if report.warn_sequential:    score += WEIGHTS['sequential']
    if report.warn_repeated:      score += WEIGHTS['repeated']
    if report.warn_leet:          score += WEIGHTS['leet']
    if report.warn_suffix:        score += WEIGHTS['bad_suffix']
    if report.warn_prefix:        score += WEIGHTS['bad_prefix']

    # Clamp: score can never go below 0 or above 100
    report.score = max(0, min(100, score))

    # ── Step 4: Assign strength label and color ───────────────────────────
    # Color values are CSS class names — used by the web UI in Phase 4
    if report.score >= 80:
        report.strength_label = "Very Strong"
        report.strength_color = "very-strong"
    elif report.score >= 60:
        report.strength_label = "Strong"
        report.strength_color = "strong"
    elif report.score >= 40:
        report.strength_label = "Moderate"
        report.strength_color = "moderate"
    elif report.score >= 20:
        report.strength_label = "Weak"
        report.strength_color = "weak"
    else:
        report.strength_label = "Very Weak"
        report.strength_color = "very-weak"

    # ── Step 5: Build suggestions list ───────────────────────────────────
    suggestions = []

    if report.length < 12:
        suggestions.append("Use at least 12 characters — 16 or more is ideal")
    if not report.check_uppercase:
        suggestions.append("Add uppercase letters (A–Z)")
    if not report.check_lowercase:
        suggestions.append("Add lowercase letters (a–z)")
    if not report.check_digit:
        suggestions.append("Add numbers (0–9)")
    if not report.check_special:
        suggestions.append("Add special characters like ! @ # $ % ^ & *")
    if report.is_common:
        suggestions.append("This is one of the most common passwords — change it immediately")
    if report.warn_sequential:
        suggestions.append("Avoid sequential characters like 'abc' or '123'")
    if report.warn_repeated:
        suggestions.append("Avoid repeated characters like 'aaa' or '111'")
    if report.warn_leet:
        suggestions.append(
            "Leet-speak substitutions (@ for a, 3 for e) don't fool modern attackers"
        )
    if report.warn_suffix:
        suggestions.append("Avoid common endings like '123', '2024', or '!'")
    if report.warn_prefix:
        suggestions.append("Avoid starting with obvious words like 'pass' or 'admin'")
    if report.breach_count > 0:
        suggestions.append(
            f"This password appeared in {report.breach_count:,} real data breaches — "
            "never use it for any account"
        )

    if not suggestions:
        suggestions.append(
            "Excellent password! Store it in a password manager like Bitwarden or KeePass"
        )

    report.suggestions = suggestions
    return report