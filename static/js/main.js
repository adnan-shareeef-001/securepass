// ── Element references ────────────────────────────────────────────────────
// We grab all the DOM elements we'll need once at the top.
// Grabbing them repeatedly inside functions is wasteful.

const passwordInput = document.getElementById('password-input');
const toggleBtn = document.getElementById('toggle-visibility');
const strengthBar = document.getElementById('strength-bar');
const strengthLabel = document.getElementById('strength-label');
const analyzeBtn = document.getElementById('analyze-btn');
const breachCheckbox = document.getElementById('breach-check');
const resultsSection = document.getElementById('results-section');
const loadingEl = document.getElementById('loading');
const scoreNumber = document.getElementById('score-number');
const scoreCircle = document.getElementById('score-circle');
const scoreStrength = document.getElementById('score-strength');
const scoreStats = document.getElementById('score-stats');
const checkList = document.getElementById('check-list');
const warningList = document.getElementById('warning-list');
const breachCard = document.getElementById('breach-card');
const suggestionList = document.getElementById('suggestion-list');


// ── Color map ─────────────────────────────────────────────────────────────
// Maps strength_color values from Python to CSS class names
const COLOR_MAP = {
    'very-weak': '#ff4757',
    'weak': '#ff6b35',
    'moderate': '#ffa502',
    'strong': '#2ed573',
    'very-strong': '#1e90ff',
};


// ── Show/hide password ────────────────────────────────────────────────────
toggleBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleBtn.textContent = isPassword ? '👀' : '🙈';
});


// ── Live strength bar as user types ──────────────────────────────────────
// This runs a lightweight LOCAL estimate — no server call.
// The full server analysis happens only when you click Analyze.

passwordInput.addEventListener('input', () => {
    const pw = passwordInput.value;

    if (!pw) {
        strengthBar.style.width = '0%';
        strengthBar.className = 'strength-bar';
        strengthLabel.textContent = 'Enter a password above';
        strengthLabel.style.color = '';
        return;
    }

    // Quick local score estimate
    let quick = 0;
    if (pw.length >= 8) quick += 20;
    if (pw.length >= 12) quick += 15;
    if (pw.length >= 16) quick += 10;
    if (/[A-Z]/.test(pw)) quick += 15;
    if (/[a-z]/.test(pw)) quick += 10;
    if (/[0-9]/.test(pw)) quick += 15;
    if (/[^A-Za-z0-9]/.test(pw)) quick += 15;
    quick = Math.min(100, quick);

    // Pick color and label based on quick score
    let color, label;
    if (quick >= 80) { color = 'very-strong'; label = 'Very Strong'; }
    else if (quick >= 60) { color = 'strong'; label = 'Strong'; }
    else if (quick >= 40) { color = 'moderate'; label = 'Moderate'; }
    else if (quick >= 20) { color = 'weak'; label = 'Weak'; }
    else { color = 'very-weak'; label = 'Very Weak'; }

    strengthBar.style.width = quick + '%';
    strengthBar.style.background = COLOR_MAP[color];
    strengthLabel.textContent = label;
    strengthLabel.style.color = COLOR_MAP[color];
});


// ── Enter key triggers analyze ────────────────────────────────────────────
passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeBtn.click();
});


// ── Main analyze function ─────────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {

    const password = passwordInput.value.trim();

    if (!password) {
        passwordInput.focus();
        passwordInput.style.borderColor = '#ff4757';
        setTimeout(() => passwordInput.style.borderColor = '', 1000);
        return;
    }

    // Show loading, hide old results
    analyzeBtn.disabled = true;
    resultsSection.style.display = 'none';
    loadingEl.style.display = breachCheckbox.checked ? 'block' : 'none';

    try {
        // Send POST request to Flask /analyze endpoint
        // The body is JSON: { password: "...", check_breach: true/false }
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                password: password,
                check_breach: breachCheckbox.checked,
            }),
        });

        // Parse the JSON response from Flask
        const data = await response.json();

        if (!response.ok) {
            alert('Error: ' + (data.error || 'Something went wrong'));
            return;
        }

        // Render all the results
        renderResults(data);

    } catch (err) {
        alert('Could not connect to the server. Is Flask running?');
        console.error(err);
    } finally {
        // Always re-enable button and hide loading
        analyzeBtn.disabled = false;
        loadingEl.style.display = 'none';
    }
});


// ── Render results ────────────────────────────────────────────────────────
// This function takes the JSON from Flask and updates the page.
// No page refresh — this is what makes it feel like a real app.

function renderResults(data) {

    const color = COLOR_MAP[data.strength_color] || '#8b8fa8';

    // ── Score circle ────────────────────────────────────────
    scoreNumber.textContent = data.score;
    scoreCircle.style.borderColor = color;
    scoreNumber.style.color = color;

    // ── Strength label ──────────────────────────────────────
    scoreStrength.textContent = data.strength_label;
    scoreStrength.style.color = color;

    // ── Stats (length + entropy) ────────────────────────────
    scoreStats.innerHTML = `
    <span>Length: ${data.length} characters</span><br>
    <span>Entropy: ${data.entropy} bits</span>
  `;

    // ── Character checks ────────────────────────────────────
    const checkItems = [
        { label: 'Uppercase letters (A–Z)', pass: data.checks.uppercase },
        { label: 'Lowercase letters (a–z)', pass: data.checks.lowercase },
        { label: 'Numbers (0–9)', pass: data.checks.digit },
        { label: 'Special characters', pass: data.checks.special },
        { label: 'Sufficient length (12+)', pass: data.checks.length },
    ];

    checkList.innerHTML = checkItems.map(item => `
    <li>
      <span class="icon">${item.pass ? '✅' : '❌'}</span>
      <span style="color: ${item.pass ? 'var(--text)' : 'var(--text-muted)'}">
        ${item.label}
      </span>
    </li>
  `).join('');

    // ── Warnings ────────────────────────────────────────────
    const warnings = [];
    if (data.warnings.sequential) warnings.push('Sequential characters (abc, 123)');
    if (data.warnings.repeated) warnings.push('Repeated characters (aaa, 111)');
    if (data.warnings.suffix) warnings.push('Common ending (123, 2024, !)');
    if (data.warnings.prefix) warnings.push('Common start (pass, admin)');
    if (data.warnings.leet && data.warnings.leet.length > 0) {
        warnings.push('Leet-speak substitutions detected');
    }
    if (data.is_common) warnings.push('This is a commonly used password');

    if (warnings.length === 0) {
        warningList.innerHTML = '<li><span class="icon">✅</span> No pattern warnings</li>';
    } else {
        warningList.innerHTML = warnings.map(w => `
      <li>
        <span class="icon">⚠️</span>
        <span style="color: var(--moderate)">${w}</span>
      </li>
    `).join('');
    }

    // ── Breach result ────────────────────────────────────────
    if (data.breach_check_failed) {
        breachCard.innerHTML = `
      <p style="color: var(--text-muted)">
        ⚠️ Breach check unavailable — no internet connection
      </p>`;
    } else if (data.breach_count === 0) {
        breachCard.innerHTML = `
      <p class="breach-safe">
        ✅ Not found in any known data breaches
      </p>`;
    } else {
        breachCard.innerHTML = `
      <p class="breach-danger">
        🚨 Found in ${data.breach_count.toLocaleString()} known data breaches!
      </p>
      <p style="color: var(--text-muted); margin-top: 0.5rem; font-size: 0.85rem">
        This password has appeared in real leaked databases.
        Do not use it for any account.
      </p>`;
    }

    // ── Suggestions ──────────────────────────────────────────
    suggestionList.innerHTML = data.suggestions
        .map(s => `<li>${s}</li>`)
        .join('');

    // ── Show results, scroll into view ──────────────────────
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}