# 🔒 SecurePass — Password Strength Analyzer

A web-based password security tool built with Python and Flask.  
Evaluates passwords across multiple security dimensions and checks them  
against 10 billion+ real-world data breach records — without ever  
transmitting your actual password.

---

## 🌐 Live Demo

> Run locally — see setup instructions below.

---

## 📸 Features

- **Entropy analysis** — calculates bits of randomness using information theory
- **Pattern detection** — catches sequential chars, repeated chars, leet-speak substitutions, common prefixes and suffixes
- **Common password check** — matches against a wordlist of the most frequently used passwords
- **Breach database check** — queries [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) using k-anonymity (your password is never sent)
- **Live strength bar** — updates as you type, before hitting Analyze
- **Actionable suggestions** — specific, prioritized improvements
- **Copy summary** — export the full analysis result to clipboard

---

## 🔐 Security Concepts Demonstrated

| Concept | Where it appears |
|---|---|
| SHA-1 hashing | `checker.py` — password hashed before API call |
| K-anonymity | `checker.py` — only 5-char hash prefix sent to server |
| Entropy (Shannon) | `utils.py` — `calculate_entropy()` |
| NIST SP 800-63B | `analyzer.py` — scoring weights based on real guidelines |
| Dictionary attacks | `wordlist.py` — common password matching |
| Pattern-based attacks | `utils.py` — leet-speak, sequential, repeated detection |

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.0 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Security API | HaveIBeenPwned v3 (k-anonymity) |
| Testing | pytest |
| Version control | Git + GitHub |

---

## 📁 Project Structure

```
securepass/
│
├── securepass/             # Core Python package
│   ├── __init__.py
│   ├── analyzer.py         # Scoring engine + PasswordReport dataclass
│   ├── checker.py          # HaveIBeenPwned API integration
│   ├── utils.py            # Entropy, pattern detection, char checks
│   └── wordlist.py         # Common password loader
│
├── templates/
│   └── index.html          # Web UI (single page)
│
├── static/
│   ├── css/style.css       # Dark theme, strength colors
│   └── js/main.js          # Fetch, live bar, DOM rendering
│
├── tests/
│   └── test_analyzer.py    # 35 pytest tests across 5 groups
│
├── data/
│   └── common_passwords.txt
│
├── app.py                  # Flask server, two routes
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/securepass.git
cd securepass

# 2. Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Open your browser and go to **http://127.0.0.1:5000**

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Expected output: **35 passed**

---

## 🔍 How the Breach Check Works

```
Your password:   "hello"
       ↓
SHA-1 hash:      AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D
       ↓
Sent to API:     AAF4C   ← first 5 characters only
       ↓
API returns:     all hashes starting with AAF4C
       ↓
Checked locally: is our full hash in the list?
```

Your actual password — or its full hash — is **never transmitted**.  
This is the [k-anonymity model](https://en.wikipedia.org/wiki/K-anonymity) used in production security tools.

---

## 📊 Scoring System

| Factor | Points |
|---|---|
| Length (up to 20 chars) | +20 max |
| Uppercase letters | +10 |
| Lowercase letters | +10 |
| Numbers | +10 |
| Special characters | +15 |
| High entropy (60+ bits) | +15 |
| Medium entropy (45–60 bits) | +8 |
| Common password | −50 |
| Found in breach | −40 |
| Sequential characters | −10 |
| Repeated characters | −10 |
| Leet-speak substitution | −5 |
| Common suffix/prefix | −5 each |

---

## 🚀 Future Improvements

- [ ] Password generator with configurable rules
- [ ] Flask-Login for user accounts and history
- [ ] SQLite database to store analysis history
- [ ] Export analysis report as PDF
- [ ] Deploy to Railway or Render (free hosting)
- [ ] ZXCVBN algorithm integration (Dropbox's estimator)

---

## 📄 License

MIT — free to use, modify, and distribute.

---

## 👤 Author

**Adnan**  
B.E. AIML — Muffakham Jah College of Engineering & Technology  
[GitHub](https://github.com/adnan-shareeef-001)