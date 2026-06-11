# checks if the password appeared in real data breaches
import hashlib
import requests


def check_pwned(password: str) -> int:
    """
    Checks if a password appeared in known data breaches.
    Uses the HaveIBeenPwned API with k-anonymity.

    Returns:
        int  > 0  → number of times seen in breaches
        int  = 0  → never seen in any breach (good!)
        int  = -1 → API call failed (no internet, timeout, etc.)
    """

    # ── Step 1: SHA-1 hash the password ──────────────────────────────────
    # encode('utf-8') converts the string into raw bytes first
    # hashlib needs bytes, not a string
    # .hexdigest() gives us the hash as a readable hex string
    # .upper() converts to uppercase (API expects uppercase)
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # ── Step 2: Split into prefix and suffix ─────────────────────────────
    # prefix = first 5 chars  → sent to the API
    # suffix = remaining chars → checked locally
    prefix = sha1[:5]
    suffix = sha1[5:]

    # ── Step 3: Query the API ─────────────────────────────────────────────
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        # timeout=5 means: if no response in 5 seconds, give up
        # This prevents the app from hanging forever
        response = requests.get(url, timeout=5)

        # raise_for_status() throws an exception if HTTP error
        # e.g. 404 Not Found, 500 Server Error
        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        # No internet connection
        return -1
    except requests.exceptions.Timeout:
        # API took too long to respond
        return -1
    except requests.exceptions.HTTPError:
        # API returned 4xx or 5xx status
        return -1
    except requests.exceptions.RequestException:
        # Catch-all for any other requests error
        return -1

    # ── Step 4: Search the response for our suffix ────────────────────────
    # Each line in the response looks like:
    # "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493"
    #  ↑ hash suffix (35 chars)              ↑ breach count
    #
    # We split each line on ':' and compare the left side to our suffix
    for line in response.text.splitlines():
        parts = line.split(':')
        if len(parts) != 2:
            continue                        # skip malformed lines
        hash_suffix, count = parts
        if hash_suffix == suffix:
            return int(count)               # found — return breach count

    # Not found in any breach database
    return 0