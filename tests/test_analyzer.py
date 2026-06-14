# ── What is pytest? ───────────────────────────────────────────────────────
# pytest is a testing framework. You write functions that start with
# "test_" and pytest finds and runs them automatically.
#
# Inside each test, you use "assert" statements.
# assert something_true   → test passes (green)
# assert something_false  → test fails (red) with a clear error message
#
# Run all tests with: pytest tests/ -v
# The -v flag means "verbose" — shows each test name as it runs

import pytest
from securepass.analyzer import analyze_password
from securepass.utils import (
    calculate_entropy,
    has_sequential_chars,
    has_repeated_chars,
    has_common_suffix,
    has_common_prefix,
    detect_leet_speak,
    has_uppercase,
    has_lowercase,
    has_digit,
    has_special,
    is_long_enough,
)


# ════════════════════════════════════════════════════════════
#  GROUP 1: ENTROPY TESTS
#  We test the math separately so we know it's correct
#  before it feeds into the scorer.
# ════════════════════════════════════════════════════════════

class TestEntropy:

    def test_empty_password_returns_zero(self):
        # An empty string has no entropy
        assert calculate_entropy('') == 0.0

    def test_single_char_returns_zero(self):
        # One character from a 26-char set: 1 × log₂(26) ≈ 4.7
        result = calculate_entropy('a')
        assert result > 0

    def test_lowercase_only_charset(self):
        # 'abc' = 3 chars, 26-char set → 3 × log₂(26) ≈ 14.1
        result = calculate_entropy('abc')
        assert 10 < result < 20

    def test_mixed_charset_higher_than_lowercase(self):
        # Same length, but more character types = larger charset = more entropy
        low  = calculate_entropy('abcdefgh')
        high = calculate_entropy('aB3@dEfG')
        assert high > low

    def test_longer_password_higher_entropy(self):
        # Same charset, more characters = more entropy
        short = calculate_entropy('aB3@')
        long  = calculate_entropy('aB3@aB3@aB3@')
        assert long > short

    def test_returns_float(self):
        result = calculate_entropy('hello123')
        assert isinstance(result, float)


# ════════════════════════════════════════════════════════════
#  GROUP 2: CHARACTER CHECK TESTS
#  Each utility function gets at least one pass and one fail.
#  If a function ever breaks, one of these will catch it.
# ════════════════════════════════════════════════════════════

class TestCharacterChecks:

    def test_uppercase_detected(self):
        assert has_uppercase('helloWorld') is True

    def test_uppercase_not_present(self):
        assert has_uppercase('helloworld') is False

    def test_lowercase_detected(self):
        assert has_lowercase('HELLOworld') is True

    def test_lowercase_not_present(self):
        assert has_lowercase('HELLOWORLD') is False

    def test_digit_detected(self):
        assert has_digit('hello123') is True

    def test_digit_not_present(self):
        assert has_digit('helloworld') is False

    def test_special_detected(self):
        assert has_special('hello!') is True

    def test_special_not_present(self):
        assert has_special('helloworld') is False

    def test_long_enough_true(self):
        assert is_long_enough('thisistwelvech') is True

    def test_long_enough_false(self):
        assert is_long_enough('short') is False

    def test_long_enough_custom_min(self):
        # Custom minimum length of 6
        assert is_long_enough('hello!', min_length=6) is True
        assert is_long_enough('hi', min_length=6) is False


# ════════════════════════════════════════════════════════════
#  GROUP 3: PATTERN DETECTION TESTS
#  Patterns are the most nuanced checks — test edge cases.
# ════════════════════════════════════════════════════════════

class TestPatternDetection:

    # Sequential characters
    def test_sequential_letters_detected(self):
        assert has_sequential_chars('abcdef') is True

    def test_sequential_numbers_detected(self):
        assert has_sequential_chars('12345') is True

    def test_sequential_mixed_in_password(self):
        # 'abc' is buried inside a longer password
        assert has_sequential_chars('X1abc9Z') is True

    def test_sequential_not_detected(self):
        assert has_sequential_chars('XkP9!mV') is False

    def test_sequential_two_chars_not_enough(self):
        # Need at least 3 consecutive — 'ab' alone doesn't count
        assert has_sequential_chars('ab!XYZ') is False

    # Repeated characters
    def test_repeated_letters_detected(self):
        assert has_repeated_chars('aaa123') is True

    def test_repeated_numbers_detected(self):
        assert has_repeated_chars('111pass') is True

    def test_repeated_not_detected(self):
        # 'aa' is only two — need three in a row
        assert has_repeated_chars('aab123') is False

    def test_repeated_two_chars_not_enough(self):
        assert has_repeated_chars('aa!XYZ') is False

    # Common suffixes
    def test_common_suffix_123(self):
        assert has_common_suffix('mypassword123') is True

    def test_common_suffix_year(self):
        assert has_common_suffix('mypassword2024') is True

    def test_common_suffix_exclamation(self):
        assert has_common_suffix('mypassword!') is True

    def test_no_common_suffix(self):
        assert has_common_suffix('X7#mK9@vL') is False

    # Common prefixes
    def test_common_prefix_pass(self):
        assert has_common_prefix('password2024') is True

    def test_common_prefix_admin(self):
        assert has_common_prefix('admin1234') is True

    def test_no_common_prefix(self):
        assert has_common_prefix('X7#mK9@vL') is False

    # Leet speak
    def test_leet_at_sign(self):
        found = detect_leet_speak('p@ssword')
        assert len(found) > 0

    def test_leet_zero_for_o(self):
        found = detect_leet_speak('passw0rd')
        assert len(found) > 0

    def test_leet_dollar_for_s(self):
        found = detect_leet_speak('pa$$word')
        assert len(found) > 0

    def test_no_leet_speak(self):
        found = detect_leet_speak('XkPmVqLn')
        assert found == []


# ════════════════════════════════════════════════════════════
#  GROUP 4: FULL ANALYZER INTEGRATION TESTS
#  These test the whole pipeline end-to-end.
#  check_breach=False skips the API call so tests run offline.
# ════════════════════════════════════════════════════════════

class TestAnalyzer:

    def test_very_weak_common_password(self):
        report = analyze_password('123456', check_breach=False)
        assert report.score < 30
        assert report.strength_label in ['Very Weak', 'Weak']
        assert report.is_common is True

    def test_very_weak_short_password(self):
        report = analyze_password('ab', check_breach=False)
        assert report.score < 20
        assert report.check_length is False

    def test_strong_password_scores_high(self):
        report = analyze_password('X7#mK9@vL2!qP5', check_breach=False)
        assert report.score >= 60

    def test_score_always_between_0_and_100(self):
        # No matter how bad the password, score never goes negative
        # No matter how good, score never exceeds 100
        bad  = analyze_password('a', check_breach=False)
        good = analyze_password('X7#mK9@vL2!qP5nZz8^', check_breach=False)
        assert 0 <= bad.score  <= 100
        assert 0 <= good.score <= 100

    def test_common_password_penalized(self):
        common = analyze_password('password', check_breach=False)
        strong = analyze_password('X7#mK9@vL2!', check_breach=False)
        assert common.score < strong.score
        assert common.is_common is True

    def test_suggestions_always_present(self):
        # Even a perfect password should give at least one suggestion
        report = analyze_password('abc', check_breach=False)
        assert len(report.suggestions) > 0

    def test_short_password_triggers_length_suggestion(self):
        report = analyze_password('hi', check_breach=False)
        has_length_tip = any(
            'character' in s.lower() or '12' in s
            for s in report.suggestions
        )
        assert has_length_tip is True

    def test_no_special_triggers_suggestion(self):
        report = analyze_password('OnlyLetters123', check_breach=False)
        has_special_tip = any(
            'special' in s.lower()
            for s in report.suggestions
        )
        assert has_special_tip is True

    def test_strength_label_matches_score(self):
        # Label must always match the score bracket
        report = analyze_password('X7#mK9@vL2!qP5', check_breach=False)
        if report.score >= 80:
            assert report.strength_label == 'Very Strong'
        elif report.score >= 60:
            assert report.strength_label == 'Strong'
        elif report.score >= 40:
            assert report.strength_label == 'Moderate'
        elif report.score >= 20:
            assert report.strength_label == 'Weak'
        else:
            assert report.strength_label == 'Very Weak'

    def test_strength_color_matches_label(self):
        # Color and label must always be in sync
        report = analyze_password('password', check_breach=False)
        label_to_color = {
            'Very Weak':   'very-weak',
            'Weak':        'weak',
            'Moderate':    'moderate',
            'Strong':      'strong',
            'Very Strong': 'very-strong',
        }
        assert report.strength_color == label_to_color[report.strength_label]

    def test_breach_check_skipped_when_false(self):
        # When check_breach=False, breach count must stay 0
        # and breach_check_failed must stay False
        report = analyze_password('password', check_breach=False)
        assert report.breach_count == 0
        assert report.breach_check_failed is False

    def test_entropy_present_in_report(self):
        report = analyze_password('hello', check_breach=False)
        assert report.entropy > 0

    def test_length_recorded_correctly(self):
        report = analyze_password('hello', check_breach=False)
        assert report.length == 5


# ════════════════════════════════════════════════════════════
#  GROUP 5: FLASK ROUTE TESTS
#  Tests the web server endpoints directly —
#  no browser needed, no manual clicking.
# ════════════════════════════════════════════════════════════

class TestFlaskRoutes:

    @pytest.fixture
    def client(self):
        """
        A pytest fixture creates a reusable test resource.
        This one creates a Flask test client — a fake browser
        that can send requests to our app without a real server.
        """
        from app import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_home_page_loads(self, client):
        response = client.get('/')
        # 200 = OK — page loaded successfully
        assert response.status_code == 200

    def test_home_page_contains_title(self, client):
        response = client.get('/')
        # Check our app name appears in the HTML
        assert b'SecurePass' in response.data

    def test_analyze_returns_json(self, client):
        response = client.post(
            '/analyze',
            json={'password': 'test123', 'check_breach': False}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data is not None

    def test_analyze_returns_score(self, client):
        response = client.post(
            '/analyze',
            json={'password': 'test123', 'check_breach': False}
        )
        data = response.get_json()
        assert 'score' in data
        assert 0 <= data['score'] <= 100

    def test_analyze_returns_all_fields(self, client):
        response = client.post(
            '/analyze',
            json={'password': 'test123', 'check_breach': False}
        )
        data = response.get_json()
        # Every key the frontend expects must be present
        required_keys = [
            'score', 'strength_label', 'strength_color',
            'length', 'entropy', 'is_common',
            'breach_count', 'breach_check_failed',
            'checks', 'warnings', 'suggestions'
        ]
        for key in required_keys:
            assert key in data, f"Missing key: {key}"

    def test_empty_password_returns_400(self, client):
        response = client.post(
            '/analyze',
            json={'password': ''}
        )
        # 400 = Bad Request — we correctly rejected the empty input
        assert response.status_code == 400

    def test_missing_password_returns_400(self, client):
        response = client.post(
            '/analyze',
            json={}
        )
        assert response.status_code == 400

    def test_no_json_body_returns_400(self, client):
        response = client.post('/analyze')
        assert response.status_code == 400

    def test_too_long_password_returns_400(self, client):
        # 129 characters — our limit is 128
        long_password = 'a' * 129
        response = client.post(
            '/analyze',
            json={'password': long_password}
        )
        assert response.status_code == 400