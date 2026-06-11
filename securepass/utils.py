# all the individual checks (entropy, patterns, character types)
import math
import re
import string


# ────────────────────────────────────────────────────────────
#  ENTROPY CALCULATION
#  Entropy = how unpredictable / random is this password?
#  Formula: length × log₂(charset_size)
#
#  Real-world meaning:
#    < 28 bits → crackable in seconds
#    28–35     → weak, crackable in minutes/hours  
#    36–59     → moderate, hours to days
#    60+       → strong, years on modern hardware
# ────────────────────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """
    Returns entropy in bits (float).
    Higher = harder to crack.
    """
    charset_size = 0

    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26      # a–z

    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26      # A–Z

    if any(c in string.digits for c in password):
        charset_size += 10      # 0–9

    if any(c in string.punctuation for c in password):
        charset_size += 32      # !@#$%^&* etc.

    if charset_size == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


# ────────────────────────────────────────────────────────────
#  CHARACTER TYPE CHECKS
#  Each returns True or False.
#  Used by the analyzer to award or deduct points.
# ────────────────────────────────────────────────────────────

def has_uppercase(password: str) -> bool:
    return any(c.isupper() for c in password)

def has_lowercase(password: str) -> bool:
    return any(c.islower() for c in password)

def has_digit(password: str) -> bool:
    return any(c.isdigit() for c in password)

def has_special(password: str) -> bool:
    return any(c in string.punctuation for c in password)

def is_long_enough(password: str, min_length: int = 12) -> bool:
    return len(password) >= min_length


# ────────────────────────────────────────────────────────────
#  PATTERN DETECTION
#  Attackers don't just try random characters — they try
#  predictable human patterns first. We detect those here.
# ────────────────────────────────────────────────────────────

# Leet-speak: users think replacing 'a' with '@' is clever.
# Attackers have dictionaries for ALL these substitutions.
LEET_PATTERNS = {
    r'[@4]':  'a-substitution (@,4)',
    r'[3€]':  'e-substitution (3,€)',
    r'[1!|]': 'i-substitution (1,!)',
    r'[0]':   'o-substitution (0)',
    r'[$5]':  's-substitution ($,5)',
    r'[7]':   't-substitution (7)',
}

# Users commonly add these at the end — attackers know this
COMMON_SUFFIXES = [
    '123', '1234', '12345', '!', '!!', '1!',
    '2024', '2023', '2022', '2021', '01', '99', '00', '1'
]

# Users commonly start with these — attackers know this too
COMMON_PREFIXES = [
    'abc', '123', 'qwerty', 'pass', 'admin',
    'user', 'login', 'welcome', 'hello', 'iloveyou'
]


def has_sequential_chars(password: str) -> bool:
    """
    Detects 3+ consecutive characters in ASCII order.
    Examples: 'abc', '123', 'xyz', 'efg'
    Attackers try all sequences first before random combos.
    """
    lower = password.lower()
    for i in range(len(lower) - 2):
        if (ord(lower[i+1]) == ord(lower[i]) + 1 and
                ord(lower[i+2]) == ord(lower[i]) + 2):
            return True
    return False


def has_repeated_chars(password: str) -> bool:
    """
    Detects 3+ identical characters in a row.
    Examples: 'aaa', '111', '!!!', 'zzz'
    Adds zero entropy — might as well not be there.
    """
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False


def detect_leet_speak(password: str) -> list:
    """
    Returns a list of leet-speak patterns found.
    Empty list = none detected.
    """
    found = []
    for pattern, name in LEET_PATTERNS.items():
        if re.search(pattern, password):
            found.append(name)
    return found


def has_common_suffix(password: str) -> bool:
    """
    Checks if password ends with a known weak suffix.
    'MyDog123' — the '123' makes it much weaker.
    """
    lower = password.lower()
    return any(lower.endswith(s) for s in COMMON_SUFFIXES)


def has_common_prefix(password: str) -> bool:
    """
    Checks if password starts with a known weak prefix.
    'password2024' — obvious starting point for attackers.
    """
    lower = password.lower()
    return any(lower.startswith(p) for p in COMMON_PREFIXES)