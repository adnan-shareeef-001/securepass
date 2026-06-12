#the Flask web server
from flask import Flask, render_template, request, jsonify
from securepass.analyzer import analyze_password

# Flask(__name__) tells Flask:
# "look for templates/ and static/ folders
#  relative to THIS file's location"
app = Flask(__name__)


# ── Route 1: Home page ────────────────────────────────────────────────────
# When the browser visits http://127.0.0.1:5000/
# Flask runs this function and returns the HTML page

@app.route('/')
def index():
    return render_template('index.html')


# ── Route 2: Analyze endpoint ─────────────────────────────────────────────
# When JavaScript sends a POST request to /analyze
# Flask runs this function, calls our analyzer, returns JSON
#
# Why POST and not GET?
# GET requests put data in the URL — bad for passwords!
# POST sends data in the request body — stays out of browser history/logs

@app.route('/analyze', methods=['POST'])
def analyze():

    # request.get_json() reads the JSON body sent by the browser
    data = request.get_json()

    # Validate: did we actually receive data?
    if not data:
        return jsonify({'error': 'No data received'}), 400

    password = data.get('password', '')

    # Validate: is the password field present and non-empty?
    if not password:
        return jsonify({'error': 'Password is required'}), 400

    # Validate: reasonable length limit (prevents abuse)
    if len(password) > 128:
        return jsonify({'error': 'Password too long'}), 400

    # check_breach=True means we call HaveIBeenPwned API
    # The frontend can pass {"password": "...", "check_breach": false}
    # to skip the API call (useful for offline testing)
    check_breach = data.get('check_breach', True)

    # Run the full analysis from Phase 3
    report = analyze_password(password, check_breach=check_breach)

    # Build the JSON response
    # We convert the dataclass to a plain dict manually
    # so Flask can serialize it to JSON
    result = {
        'score':               report.score,
        'strength_label':      report.strength_label,
        'strength_color':      report.strength_color,
        'length':              report.length,
        'entropy':             report.entropy,
        'is_common':           report.is_common,
        'breach_count':        report.breach_count,
        'breach_check_failed': report.breach_check_failed,

        # Checks (True/False each)
        'checks': {
            'uppercase': report.check_uppercase,
            'lowercase': report.check_lowercase,
            'digit':     report.check_digit,
            'special':   report.check_special,
            'length':    report.check_length,
        },

        # Warnings (True/False each)
        'warnings': {
            'sequential': report.warn_sequential,
            'repeated':   report.warn_repeated,
            'leet':       report.warn_leet,
            'suffix':     report.warn_suffix,
            'prefix':     report.warn_prefix,
        },

        # List of suggestion strings
        'suggestions': report.suggestions,
    }

    return jsonify(result)


# ── Entry point ───────────────────────────────────────────────────────────
# This block only runs when you type: python app.py
# It does NOT run when Flask imports this file as a module

if __name__ == '__main__':
    # debug=True means:
    # 1. Auto-reloads when you save a file (no manual restart)
    # 2. Shows detailed error pages in the browser
    # NEVER use debug=True in production (exposes internals)
    app.run(debug=True)