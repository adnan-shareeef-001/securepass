#loads your common passwords list
import os


def load_common_passwords(filepath: str = None) -> set:
    """
    Reads common_passwords.txt and returns a Python SET.

    Why a set and not a list?
    ─────────────────────────
    Imagine checking if 'password' is in a list of 10,000 words.
    Python checks word 1... word 2... word 3... all the way down.
    That's up to 10,000 comparisons every single time.

    A set uses a hash table — it jumps straight to the answer
    in one step, no matter how big the set is.
    This is called O(1) lookup vs O(n) — a fundamental CS concept.
    """

    if filepath is None:
        # Build the path to data/common_passwords.txt
        # __file__ is the path to THIS file (wordlist.py)
        # We go up two levels to reach the project root
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = os.path.join(base_dir, 'data', 'common_passwords.txt')

    common = set()

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip().lower()
                if word:                    # skip blank lines
                    common.add(word)

    except FileNotFoundError:
        print(f"[Warning] Wordlist not found at: {filepath}")
        return set()

    return common


# ─────────────────────────────────────────────────────────
#  Load ONCE when this module is first imported.
#  Every other file that does "from securepass.wordlist import
#  COMMON_PASSWORDS" gets this same already-loaded set.
#  The file is never read from disk twice.
# ─────────────────────────────────────────────────────────
COMMON_PASSWORDS = load_common_passwords()