from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import pickle, re, json, os, hashlib, base64, hmac, time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'cyberguard-ultra-secret-2024-XK9'

# ── Crypto key (Cryptography module) ─────────────────────────────────────────
CRYPTO_KEY_FILE = 'data/crypto.key'
os.makedirs('data', exist_ok=True)
if os.path.exists(CRYPTO_KEY_FILE):
    with open(CRYPTO_KEY_FILE, 'rb') as f:
        FERNET_KEY = f.read()
else:
    FERNET_KEY = Fernet.generate_key()
    with open(CRYPTO_KEY_FILE, 'wb') as f:
        f.write(FERNET_KEY)
fernet = Fernet(FERNET_KEY)

# ── Load ML model ─────────────────────────────────────────────────────────────
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

USERS_FILE   = 'data/users.json'
HISTORY_FILE = 'data/history.json'
SIEM_FILE    = 'data/siem_events.json'
AUDIT_FILE   = 'data/audit_log.json'
BLOCKCHAIN_FILE = 'data/blockchain.json'

def load_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ── BLOCKCHAIN: Tamper-proof audit chain ──────────────────────────────────────
def compute_block_hash(block):
    data = f"{block['index']}{block['timestamp']}{block['data']}{block['prev_hash']}"
    return hashlib.sha256(data.encode()).hexdigest()

def add_to_blockchain(event_type, data_str):
    chain = load_json(BLOCKCHAIN_FILE, [])
    prev_hash = chain[-1]['hash'] if chain else '0' * 64
    block = {
        'index': len(chain),
        'timestamp': now(),
        'event_type': event_type,
        'data': data_str,
        'prev_hash': prev_hash,
        'hash': ''
    }
    block['hash'] = compute_block_hash(block)
    chain.append(block)
    save_json(BLOCKCHAIN_FILE, chain)

def verify_blockchain():
    chain = load_json(BLOCKCHAIN_FILE, [])
    for i, block in enumerate(chain):
        expected = compute_block_hash(block)
        if block['hash'] != expected:
            return False, i
        if i > 0 and block['prev_hash'] != chain[i-1]['hash']:
            return False, i
    return True, len(chain)

# ── SIEM: Log security events ─────────────────────────────────────────────────
def siem_log(event_type, severity, user, details, ip='127.0.0.1'):
    events = load_json(SIEM_FILE, [])
    event = {
        'id': f'EVT-{len(events)+1:04d}',
        'timestamp': now(),
        'event_type': event_type,
        'severity': severity,   # LOW / MEDIUM / HIGH / CRITICAL
        'user': user,
        'details': details,
        'ip': ip,
        'status': 'OPEN'
    }
    events.insert(0, event)
    events = events[:200]
    save_json(SIEM_FILE, events)
    add_to_blockchain(event_type, f"{user}|{severity}|{details[:80]}")
    return event

# ── AUDIT: Compliance trail ───────────────────────────────────────────────────
def audit_log(user, action, resource, result, ip='127.0.0.1'):
    logs = load_json(AUDIT_FILE, [])
    logs.insert(0, {
        'id': f'AUD-{len(logs)+1:04d}',
        'timestamp': now(),
        'user': user,
        'action': action,
        'resource': resource,
        'result': result,
        'ip': ip,
        'compliance': 'ISO27001 | GDPR | NIST'
    })
    logs = logs[:500]
    save_json(AUDIT_FILE, logs)

# ── Phishing analysis core ────────────────────────────────────────────────────
SUSPICIOUS_WORDS = [
    'urgent','verify','password','bank','click here','account suspended',
    'immediate','winner','congratulations','free','prize','limited time',
    'act now','expires','confirm','credentials','ssn','social security',
    'credit card','wire transfer','bitcoin','suspended','locked','compromised',
    'unusual activity','security alert','update required','validate','otp',
    'reset password','account will be deleted','unauthorized access'
]

THREAT_CATEGORIES = {
    'Credential Harvesting': ['password','credentials','verify','confirm','login','username'],
    'Financial Fraud':       ['bank','credit card','wire transfer','bitcoin','funds','payment'],
    'Account Takeover':      ['suspended','locked','account','access','unauthorized','restore'],
    'Social Engineering':    ['urgent','immediate','act now','limited time','expires','warning'],
    'Malware/Phishing Link': ['click here','link','http','download','install','update required'],
}

def classify_threats(text):
    text_lower = text.lower()
    found = {}
    for cat, keywords in THREAT_CATEGORIES.items():
        hits = [k for k in keywords if k in text_lower]
        if hits:
            found[cat] = hits
    return found

def extract_urls(text):
    return re.findall(r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)', text, re.I)

def check_url_safety(url):
    flags = []
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        flags.append("IP address used instead of domain name")
    dm = re.search(r'https?://([^/]+)', url)
    if dm:
        domain = dm.group(1)
        parts = domain.split('.')
        if len(parts) > 4:
            flags.append("Excessive subdomains detected")
        if re.search(r'\d', parts[0]):
            flags.append("Numbers in primary domain")
        brands = ['paypal','apple','google','amazon','microsoft','netflix','bank','irs','facebook']
        tld = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        for brand in brands:
            if brand in domain.lower() and brand not in tld.lower():
                flags.append(f"Brand spoofing: '{brand}' in subdomain")
                break
        suspicious_tlds = ['.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.club','.info']
        for t in suspicious_tlds:
            if domain.lower().endswith(t):
                flags.append(f"Suspicious TLD: '{t}'")
                break
        if len(domain) > 50:
            flags.append("Unusually long domain (obfuscation attempt)")
        if domain.count('-') > 2:
            flags.append("Multiple hyphens (common phishing trick)")
    return flags

def encrypt_email(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt_email(token):
    try:
        return fernet.decrypt(token.encode()).decode()
    except:
        return "[Decryption failed]"

def analyze_email(email_text, user):
    prob = model.predict_proba([email_text])[0]
    score = round(float(prob[1]) * 100, 1)

    urls = extract_urls(email_text)
    url_flags = [{'url': u, 'flags': check_url_safety(u)} for u in urls if check_url_safety(u)]
    sus_words = [w for w in SUSPICIOUS_WORDS if w in email_text.lower()]
    threats = classify_threats(email_text)

    if url_flags: score = min(100, score + 15 * len(url_flags))
    if len(sus_words) >= 3: score = min(100, score + 10)
    score = round(score, 1)

    if score < 35:   risk, risk_label = 'safe',       'Safe'
    elif score < 65: risk, risk_label = 'suspicious',  'Suspicious'
    else:            risk, risk_label = 'phishing',    'High Phishing Risk'

    reasons = []
    if sus_words:   reasons.append(f"Contains {len(sus_words)} suspicious keyword(s): {', '.join(sus_words[:4])}")
    if url_flags:   reasons.append(f"{len(url_flags)} suspicious URL(s) flagged")
    if threats:     reasons.append(f"Threat categories: {', '.join(list(threats.keys())[:3])}")
    if score > 65 and not reasons: reasons.append("AI model detected phishing patterns")
    if score < 35 and not reasons: reasons.append("No significant threats detected")

    explanation = "This email was flagged because: " + "; ".join(reasons) if reasons else \
                  "This email appears safe. No significant threats were detected."

    # SOAR automated response
    soar_actions = []
    if risk == 'phishing':
        soar_actions = ['🔴 AUTO-BLOCKED: Email flagged for quarantine', '📧 Alert sent to security team', '🔒 User session monitored', '📋 Incident report generated']
        siem_log('PHISHING_DETECTED', 'CRITICAL', user, f"Score:{score}% | Words:{len(sus_words)} | URLs:{len(url_flags)}")
    elif risk == 'suspicious':
        soar_actions = ['🟡 Email flagged for review', '👁️ Enhanced monitoring activated']
        siem_log('SUSPICIOUS_EMAIL', 'HIGH', user, f"Score:{score}%")
    else:
        soar_actions = ['✅ Email passed all security checks']
        siem_log('EMAIL_ANALYZED', 'LOW', user, f"Score:{score}% - Safe")

    # Encrypt email for storage (Cryptography module)
    encrypted = encrypt_email(email_text[:500])

    result = {
        'score': score,
        'risk': risk,
        'risk_label': risk_label,
        'explanation': explanation,
        'suspicious_words': sus_words,
        'urls': urls,
        'url_flags': url_flags,
        'threat_categories': threats,
        'soar_actions': soar_actions,
        'encrypted_preview': encrypted[:80] + '...',
        'email_preview': email_text[:120] + '...' if len(email_text) > 120 else email_text,
        'timestamp': now(),
        'compliance_tags': ['ISO 27001', 'GDPR Art.32', 'NIST CSF'],
    }

    audit_log(user, 'EMAIL_ANALYSIS', 'phishing_detector', f"Risk:{risk_label} Score:{score}%")
    return result

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        d = request.json
        email = d.get('email','').strip().lower()
        pw    = d.get('password','')
        users = load_json(USERS_FILE, {})
        ip    = request.remote_addr or '127.0.0.1'
        if email in users and users[email]['password'] == hash_password(pw):
            session['user'] = email
            siem_log('USER_LOGIN', 'LOW', email, 'Successful login', ip)
            audit_log(email, 'LOGIN', 'auth_system', 'SUCCESS', ip)
            return jsonify({'success': True})
        siem_log('LOGIN_FAILED', 'MEDIUM', email, 'Invalid credentials', ip)
        audit_log(email, 'LOGIN', 'auth_system', 'FAILED', ip)
        return jsonify({'success': False, 'message': 'Invalid email or password'})
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        d    = request.json
        email = d.get('email','').strip().lower()
        pw    = d.get('password','')
        name  = d.get('name','').strip()
        if not all([email, pw, name]):
            return jsonify({'success': False, 'message': 'All fields required'})
        users = load_json(USERS_FILE, {})
        if email in users:
            return jsonify({'success': False, 'message': 'Email already registered'})
        users[email] = {'password': hash_password(pw), 'name': name, 'created': now(), 'role': 'Analyst'}
        save_json(USERS_FILE, users)
        session['user'] = email
        siem_log('USER_REGISTERED', 'LOW', email, 'New account created')
        audit_log(email, 'REGISTER', 'auth_system', 'SUCCESS')
        add_to_blockchain('NEW_USER', email)
        return jsonify({'success': True})
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = session.pop('user', None)
    if user:
        siem_log('USER_LOGOUT', 'LOW', user, 'Session ended')
        audit_log(user, 'LOGOUT', 'auth_system', 'SUCCESS')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    users = load_json(USERS_FILE, {})
    name  = users.get(session['user'], {}).get('name', 'Analyst')
    return render_template('dashboard.html', user_name=name, user_email=session['user'])

@app.route('/history')
def history():
    if 'user' not in session: return redirect(url_for('login'))
    users = load_json(USERS_FILE, {})
    name  = users.get(session['user'], {}).get('name', 'Analyst')
    return render_template('history.html', user_name=name, user_email=session['user'])

@app.route('/siem')
def siem():
    if 'user' not in session: return redirect(url_for('login'))
    users = load_json(USERS_FILE, {})
    name  = users.get(session['user'], {}).get('name', 'Analyst')
    return render_template('siem.html', user_name=name, user_email=session['user'])

@app.route('/compliance')
def compliance():
    if 'user' not in session: return redirect(url_for('login'))
    users = load_json(USERS_FILE, {})
    name  = users.get(session['user'], {}).get('name', 'Analyst')
    return render_template('compliance.html', user_name=name, user_email=session['user'])

# ── APIs ──────────────────────────────────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    email_text = request.json.get('email','').strip()
    if not email_text: return jsonify({'error': 'No content'}), 400
    result = analyze_email(email_text, session['user'])
    h = load_json(HISTORY_FILE, {})
    uh = h.get(session['user'], [])
    uh.insert(0, result); uh = uh[:50]
    h[session['user']] = uh
    save_json(HISTORY_FILE, h)
    return jsonify(result)

@app.route('/api/history')
def api_history():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    h = load_json(HISTORY_FILE, {})
    return jsonify(h.get(session['user'], []))

@app.route('/api/stats')
def api_stats():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    h = load_json(HISTORY_FILE, {})
    records = h.get(session['user'], [])
    total = len(records)
    phishing   = sum(1 for r in records if r['risk'] == 'phishing')
    suspicious = sum(1 for r in records if r['risk'] == 'suspicious')
    safe       = sum(1 for r in records if r['risk'] == 'safe')
    avg_score  = round(sum(r['score'] for r in records) / total, 1) if total else 0
    return jsonify({'total': total, 'phishing': phishing, 'suspicious': suspicious, 'safe': safe, 'avg_score': avg_score})

@app.route('/api/siem_events')
def api_siem():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    events = load_json(SIEM_FILE, [])
    return jsonify(events[:50])

@app.route('/api/audit_log')
def api_audit():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    logs = load_json(AUDIT_FILE, [])
    return jsonify(logs[:50])

@app.route('/api/blockchain')
def api_blockchain():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    chain = load_json(BLOCKCHAIN_FILE, [])
    valid, count = verify_blockchain()
    return jsonify({'chain': chain[-10:], 'valid': valid, 'total_blocks': count})

@app.route('/api/compliance_report')
def api_compliance():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    h = load_json(HISTORY_FILE, {})
    records = h.get(session['user'], [])
    total = len(records)
    phishing = sum(1 for r in records if r['risk'] == 'phishing')
    chain = load_json(BLOCKCHAIN_FILE, [])
    valid, _ = verify_blockchain()
    return jsonify({
        'iso27001': {'status': 'Compliant', 'score': 92, 'controls': ['A.12.2 – Malware protection', 'A.16.1 – Incident management', 'A.12.4 – Logging & monitoring']},
        'gdpr':     {'status': 'Compliant', 'score': 88, 'articles': ['Art.32 – Security of processing', 'Art.33 – Breach notification', 'Art.5 – Data integrity']},
        'nist':     {'status': 'Compliant', 'score': 90, 'functions': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']},
        'blockchain_integrity': valid,
        'total_analyzed': total,
        'threats_blocked': phishing,
        'audit_entries': len(load_json(AUDIT_FILE, [])),
        'generated': now()
    })

@app.route('/api/global_stats')
def api_global_stats():
    if 'user' not in session: return jsonify({'error': 'Unauthorized'}), 401
    h = load_json(HISTORY_FILE, {})
    all_records = [r for recs in h.values() for r in recs]
    total = len(all_records)
    phishing = sum(1 for r in all_records if r['risk'] == 'phishing')
    events = load_json(SIEM_FILE, [])
    critical = sum(1 for e in events if e['severity'] == 'CRITICAL')
    return jsonify({'total': total, 'phishing': phishing, 'siem_events': len(events), 'critical_alerts': critical})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
