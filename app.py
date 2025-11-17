from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from datetime import datetime
from collections import Counter
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database setup
def init_db():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  ip_address TEXT,
                  username TEXT,
                  password TEXT,
                  user_agent TEXT,
                  url TEXT,
                  attack_type TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Log attack function
def log_attack(username='', password='', url='', attack_type=''):
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute('''INSERT INTO attacks 
                 (timestamp, ip_address, username, password, user_agent, url, attack_type)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(),
               request.remote_addr,
               username,
               password,
               request.headers.get('User-Agent', ''),
               url,
               attack_type))
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        log_attack(username, password, '/admin', 'login_attempt')
        return render_template('admin.html', error='There was a problem. Incorrect email or password.')
    return render_template('admin.html')

# Trap URLs
@app.route('/backup.sql')
def trap_backup():
    log_attack(url='/backup.sql', attack_type='trap_file')
    return 'File not found', 404

@app.route('/config.php')
def trap_config():
    log_attack(url='/config.php', attack_type='trap_file')
    return 'File not found', 404

@app.route('/wp-admin')
@app.route('/wp-admin/')
def trap_wordpress():
    log_attack(url='/wp-admin', attack_type='trap_file')
    return 'Not found', 404

@app.route('/database.sql')
def trap_database():
    log_attack(url='/database.sql', attack_type='trap_file')
    return 'Not found', 404

# Real Dashboard
@app.route('/honeypot-dashboard', methods=['GET', 'POST'])
def dashboard_login():
    if 'authenticated' in session:
        return redirect('/dashboard')
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == 'SecurePass123':  # Change this password!
            session['authenticated'] = True
            return redirect('/dashboard')
    
    return render_template('dashboard_login.html')

@app.route('/dashboard')
def dashboard():
    if 'authenticated' not in session:
        return redirect('/honeypot-dashboard')
    
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM attacks')
    total_attacks = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT ip_address) FROM attacks')
    unique_ips = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM attacks WHERE attack_type='login_attempt'")
    login_attempts = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM attacks WHERE attack_type='trap_file'")
    trap_accesses = c.fetchone()[0]
    
    # Recent attacks
    c.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 20')
    recent_attacks = c.fetchall()
    
    # Top usernames
    c.execute("SELECT username, COUNT(*) as count FROM attacks WHERE username != '' GROUP BY username ORDER BY count DESC LIMIT 10")
    top_usernames = c.fetchall()
    
    # Top IPs
    c.execute('SELECT ip_address, COUNT(*) as count FROM attacks GROUP BY ip_address ORDER BY count DESC LIMIT 10')
    top_ips = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         total_attacks=total_attacks,
                         unique_ips=unique_ips,
                         login_attempts=login_attempts,
                         trap_accesses=trap_accesses,
                         recent_attacks=recent_attacks,
                         top_usernames=top_usernames,
                         top_ips=top_ips)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect('/honeypot-dashboard')

if __name__ == '__main__':
    app.run()
