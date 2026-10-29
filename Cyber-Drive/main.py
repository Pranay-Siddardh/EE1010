import os
import json
import shutil
import zipfile
import io
import subprocess
import secrets
import hmac
import re
import subprocess
import tempfile
import time
import smtplib
import hashlib
import threading
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, abort, redirect, request, session, url_for, send_from_directory, send_file, jsonify, render_template_string, flash

# Load private settings from a .env file beside this script, if python-dotenv is installed.
# Real environment variables take precedence over values in .env.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except ImportError:
    pass  # Install python-dotenv to enable automatic .env loading.

app = Flask(__name__)

# Readable terminal logs: timestamp, severity, request/action context.
import logging
for _existing_handler in list(app.logger.handlers):
    app.logger.removeHandler(_existing_handler)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)-8s | CYBER-DRIVE | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'))
app.logger.addHandler(_console_handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False

# Keep the session-signing key stable across restarts. Prefer an environment
# variable in production; otherwise create a local key file with restrictive permissions.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_FILE = os.path.join(APP_DIR, '.cyber_drive_secret')
def load_secret_key():
    configured = os.environ.get('CYBER_DRIVE_SECRET_KEY')
    if configured:
        if len(configured) < 32:
            raise RuntimeError('CYBER_DRIVE_SECRET_KEY must be at least 32 characters.')
        return configured
    try:
        with open(SECRET_KEY_FILE, 'rb') as key_file:
            key = key_file.read()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(48)
    fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as key_file:
        key_file.write(key)
    return key

app.secret_key = load_secret_key()
HTTPS_ONLY = os.environ.get('CYBER_DRIVE_HTTPS', '0') == '1'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=HTTPS_ONLY,
    MAX_CONTENT_LENGTH=MAX_STORAGE_BYTES if 'MAX_STORAGE_BYTES' in globals() else 5 * 1024 * 1024 * 1024,
)

# Optional integrations are configured through environment variables; never hard-code secrets.
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
# Google requires an allowed redirect URI. For LAN-only hosting, a private IP such as
# http://10.1.139.176:80 is not a suitable Google web OAuth redirect URI. Set this to
# a public HTTPS base URL (for example, a domain or HTTPS tunnel) when one is available.
# For testing on the same machine only, localhost can be used as the base URL. Default: http://localhost:6969.
GOOGLE_OAUTH_BASE_URL = os.environ.get('CYBER_DRIVE_OAUTH_BASE_URL', 'http://localhost:80').strip().rstrip('/')

# Google OAuth is enabled only when Authlib, credentials, and a valid callback base URL exist.
# This prevents generating a callback URL based on the private LAN IP that Google rejects.
google_oauth = None
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_OAUTH_BASE_URL:
    try:
        from authlib.integrations.flask_client import OAuth
        oauth = OAuth(app)
        google_oauth = oauth.register(
            name='google',
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'},
        )
    except ImportError:
        app.logger.warning('Google sign-in is disabled: install Authlib to enable it.')
elif GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    app.logger.warning('Google sign-in credentials exist, but CYBER_DRIVE_OAUTH_BASE_URL is not set. Google sign-in stays disabled because this server is LAN-only.')

BASE_STORAGE_DIR = os.path.join(APP_DIR, 'storage')
USERS_FILE = os.path.join(APP_DIR, 'users.json')
SESSION_LOG_DIR = os.path.join(APP_DIR, 'login_logs')
ADMIN_DIR = os.path.join(APP_DIR, '.admin')
ADMIN_FILE = os.path.join(ADMIN_DIR, '.admin_credentials.json')
STORAGE_REQUESTS_FILE = os.path.join(APP_DIR, 'storage_requests.json')
ADMIN_SETTINGS_FILE = os.path.join(ADMIN_DIR, '.admin_settings.json')
ADMIN_AUDIT_FILE = os.path.join(ADMIN_DIR, '.admin_audit.json')
MAX_USER_STORAGE_BYTES = 10 * 1024 * 1024 * 1024
RESET_OTP_TTL_SECONDS = 120
RESET_OTP_COOLDOWN_SECONDS = 30
SIGNUP_OTP_TTL_SECONDS = 120
SIGNUP_OTP_RESEND_SECONDS = 30
DEFAULT_STORAGE_BYTES = 1 * 1024 * 1024 * 1024
MAX_USER_ACCOUNTS = 5  # Default; the admin can raise this limit.
# In-process reservations prevent simultaneous uploads from oversubscribing quotas.
UPLOAD_RESERVATION_LOCK = threading.RLock()
UPLOAD_RESERVATIONS = {}  # token -> {username, bytes, created}
os.makedirs(SESSION_LOG_DIR, exist_ok=True)

# Admin credentials are stored in a separate hidden file; settings stay in .admin/.
# Migrate credentials from older layouts without overwriting an existing credentials file.
def prepare_admin_directory():
    os.makedirs(ADMIN_DIR, mode=0o700, exist_ok=True)
    legacy_root_file = os.path.join(APP_DIR, '.admin_credentials.json')
    legacy_nested = os.path.join(ADMIN_DIR, 'credentials.json')
    legacy_old_file = os.path.join(APP_DIR, '.admin')
    if not os.path.exists(ADMIN_FILE):
        # Migrate prior credential-file layouts once, without overwriting the new location.
        for source in (legacy_root_file, legacy_nested, legacy_old_file):
            if os.path.isfile(source):
                try:
                    os.replace(source, ADMIN_FILE)
                    app.logger.info('Migrated admin credentials into .admin/.admin_credentials.json.')
                    break
                except OSError:
                    app.logger.exception('Could not migrate legacy admin credentials into .admin/.admin_credentials.json.')
    for path in (ADMIN_DIR, ADMIN_FILE):
        try:
            if os.path.isdir(path):
                os.chmod(path, 0o700)
            elif os.path.isfile(path):
                os.chmod(path, 0o600)
        except OSError:
            pass

# Run the private-directory preparation during startup, not only when settings change.
prepare_admin_directory()

# Email integration is configured through environment variables; never hard-code secrets.
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
MAIL_FROM = os.environ.get('MAIL_FROM', SMTP_USERNAME)
MAX_STORAGE_BYTES = 4 * 1024 * 1024 * 1024  # hard per-upload/request ceiling; total account quota may reach 10 GiB
app.config['MAX_CONTENT_LENGTH'] = MAX_STORAGE_BYTES

os.makedirs(BASE_STORAGE_DIR, exist_ok=True)

IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico'}
AUDIO_EXTS = {'.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac'}
VIDEO_EXTS = {'.mp4', '.webm', '.m4v', '.mov', '.mkv'}
DOCUMENT_EXTS = {'.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt'}
# Text/source formats opened in the built-in, read-only syntax-coloured Code Viewer.
CODE_EXTS = {
    '.txt', '.text', '.log', '.md', '.markdown', '.rst', '.csv', '.tsv', '.json', '.jsonc', '.json5',
    '.xml', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
    '.py', '.pyw', '.ipynb', '.c', '.h', '.cc', '.hh', '.cpp', '.cxx', '.hpp', '.hxx', '.ino', '.pde',
    '.java', '.kt', '.kts', '.scala', '.go', '.rs', '.swift', '.m', '.mm', '.cs', '.fs', '.vb', '.php', '.rb',
    '.r', '.R', '.jl', '.lua', '.pl', '.pm', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
    '.sql', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env', '.dockerfile', '.makefile', '.mk',
    '.cmake', '.gradle', '.properties', '.tex', '.bib', '.sty', '.cls', '.asm', '.s', '.S', '.v', '.sv',
    '.vhd', '.vhdl', '.mat', '.m', '.gitignore', '.editorconfig', '.diff', '.patch', '.graphql', '.gql',
    '.proto', '.vue', '.svelte', '.astro', '.tf', '.hcl', '.prisma', '.ipynb', '.lock'
}
OFFICE_DOCUMENT_EXTS = DOCUMENT_EXTS - {'.pdf'}

def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

app.jinja_env.globals['csrf_token'] = csrf_token

@app.before_request
def enforce_csrf_and_session_safety():
    if request.method == 'POST':
        supplied = request.headers.get('X-CSRF-Token') or request.form.get('_csrf_token', '')
        expected = session.get('_csrf_token', '')
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            # If the OTP resend form has gone stale, safely reload the signup page
            # to issue a fresh CSRF token. No resend action is performed here.
            if request.path == '/resend-signup-otp':
                return redirect(url_for('signup', csrf_refresh='1'))
            abort(400, description='Invalid or missing CSRF token.')

@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    if HTTPS_ONLY:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response

def user_root_path(folder_name):
    # Folder names from users.json must not be able to escape the storage root.
    if not isinstance(folder_name, str) or not folder_name or folder_name in {'.', '..'}:
        abort(403)
    storage_root = os.path.realpath(BASE_STORAGE_DIR)
    root = os.path.realpath(os.path.join(storage_root, folder_name))
    if os.path.commonpath([storage_root, root]) != storage_root or root == storage_root:
        abort(403)
    return root

def resolve_user_path(user_root, rel_path=''):
    # realpath + commonpath prevents traversal and symlink escapes.
    candidate = os.path.realpath(os.path.join(user_root, rel_path))
    try:
        if os.path.commonpath([os.path.realpath(user_root), candidate]) != os.path.realpath(user_root):
            abort(403)
    except ValueError:
        abort(403)
    return candidate

def safe_folder_name(name):
    name = (name or '').strip()
    if not name or name in {'.', '..'} or '/' in name or '\\' in name or '\x00' in name:
        return None
    if name.startswith('.'):
        return None
    return name

def clean_path_display(req_path, default_root_name):
    """Strips leading/trailing slashes for clean UI folder titles."""
    if not req_path:
        return default_root_name
    cleaned = req_path.replace('\\', '/').strip('/')
    return cleaned if cleaned else default_root_name

LOGIN_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Cyber Drive - Sign In</title>
    <link rel="icon" type="image/svg+xml" href="/cloud-icon.svg?v=3">
    <style>
        * { box-sizing: border-box; font-family: 'Courier New', Courier, monospace; }
        button, a, input, select, textarea, .login-card, .auth-card, .auth-tab, .login-btn {
            transition: color .22s ease, background-color .22s ease, border-color .22s ease,
                        box-shadow .28s ease, opacity .28s ease, transform .28s cubic-bezier(.2,.8,.2,1);
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
        }
        @keyframes auth-card-enter {
            from { opacity: 0; transform: translateY(12px) scale(.985); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        body {
            background: radial-gradient(circle at center, #0f172a 0%, #07090e 100%); 
            color: #e2e8f0; 
            font-family: 'Courier New', Courier, monospace; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0; 
        }
        .login-card {
            animation: auth-card-enter .5s cubic-bezier(.2,.8,.2,1) both;
            background: rgba(17, 24, 39, 0.85); 
            backdrop-filter: blur(16px);
            padding: 40px; 
            border-radius: 16px; 
            box-shadow: 0 10px 40px rgba(0, 240, 255, 0.2); 
            border: 1px solid rgba(0, 240, 255, 0.25); 
            width: 360px; 
            text-align: center; 
            animation: fadeIn 0.6s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(15px) scale(0.96); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .logo-img { width: 64px; height: 64px; margin-bottom: 12px; filter: drop-shadow(0 0 10px #00f0ff); }
        h2 { color: #00f0ff; margin: 0 0 8px 0; font-weight: 700; text-shadow: 0 0 12px rgba(0,240,255,0.4); }
        p { color: #94a3b8; font-size: 14px; margin-bottom: 25px; }
        .input-group { position: relative; margin-bottom: 18px; }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 12px 14px; 
            background: rgba(11, 15, 25, 0.8); 
            border: 1px solid #374151; 
            border-radius: 8px; 
            color: #fff; 
            font-size: 15px; 
            outline: none; 
        }
        .password-wrap { display: flex; gap: 8px; align-items: stretch; }
        .password-wrap input { flex: 1; min-width: 0; }
        .toggle-password {
            width: 48px; flex: 0 0 48px; display: inline-flex; align-items: center; justify-content: center;
            padding: 0; border: 1px solid #374151; border-radius: 8px;
            background: #1f2937; color: #00f0ff; cursor: pointer;
        }
        .toggle-password svg { width: 21px; height: 21px; display: block; }
        .toggle-password:hover { background: #263449; border-color: #00f0ff; }
        .toggle-password:focus-visible { outline: 2px solid #00f0ff; outline-offset: 2px; }
        input[type="text"]:focus, input[type="password"]:focus { 
            border-color: #00f0ff; 
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
        }
        .btn-submit { 
            width: 100%; 
            padding: 12px; 
            background: linear-gradient(135deg, #00f0ff 0%, #3b82f6 100%); 
            color: #07090e; 
            border: none; 
            border-radius: 8px; 
            font-weight: bold; 
            font-size: 16px; 
            cursor: pointer; 
            box-shadow: 0 4px 15px rgba(0, 240, 255, 0.3);
        }
        .btn-submit:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 6px 20px rgba(0, 240, 255, 0.5); 
        }
        .error { color: #f87171; font-size: 13px; margin-bottom: 15px; background: rgba(248, 113, 113, 0.1); padding: 10px; border-radius: 6px; border: 1px solid rgba(248, 113, 113, 0.3); }
    
    /* Prevent long filenames from overflowing the media viewer */
    .media-modal-card,
    .media-modal-card h3 {
        min-width: 0;
        max-width: 100%;
        box-sizing: border-box;
    }

    .media-modal-card h3 {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-start;
        gap: 10px;
    }

    #mediaTitleText {
        flex: 1 1 200px;
        min-width: 0;
        max-width: 100%;
        overflow-wrap: anywhere;
        word-break: break-word;
    }

    .media-title-actions {
        flex: 0 1 auto;
        min-width: 0;
        max-width: 100%;
        flex-wrap: wrap;
        justify-content: flex-end;
    }
    </style>
</head>
<body>
    <div class="login-card">
        <img src="/cloud-icon.svg?v=3" class="logo-img" alt="Cyber Drive Logo">
        <h2>Cyber Drive</h2>
        <p>Enter your credentials to continue</p>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <div class="input-group">
                <input type="text" name="username" placeholder="Username" required autocomplete="off">
            </div>
            <div class="input-group">
                <div class="password-wrap">
                    <input id="loginPassword" type="password" name="password" placeholder="Password" required autocomplete="current-password">
                    <button class="toggle-password" type="button" id="togglePassword" aria-label="Show password" aria-pressed="false" title="Show password">
                        <svg id="passwordEyeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                    </button>
                </div>
            </div>
            <button type="submit" class="btn-submit">Sign In</button>
        </form>
    </div>
    <script>
        const passwordInput = document.getElementById('loginPassword');
        const togglePasswordButton = document.getElementById('togglePassword');
        togglePasswordButton.addEventListener('click', function () {
            const shouldShow = passwordInput.type === 'password';
            passwordInput.type = shouldShow ? 'text' : 'password';
            togglePasswordButton.innerHTML = shouldShow
                ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a16 16 0 0 1-3.1 3.9"/><path d="M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7c1.3 0 2.5-.3 3.5-.8"/></svg>'
                : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
            togglePasswordButton.setAttribute('aria-label', shouldShow ? 'Hide password' : 'Show password');
            togglePasswordButton.setAttribute('title', shouldShow ? 'Hide password' : 'Show password');
            togglePasswordButton.setAttribute('aria-pressed', String(shouldShow));
        });
    </script>
</body>
</html>
"""

MAIN_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Cyber Drive</title>
    <link rel="icon" type="image/svg+xml" href="/cloud-icon.svg?v=3">
    <style>
        * { box-sizing: border-box; font-family: 'Courier New', Courier, monospace; }
        button, a, input, select, textarea, .login-card, .auth-card, .auth-tab, .login-btn {
            transition: color .22s ease, background-color .22s ease, border-color .22s ease,
                        box-shadow .28s ease, opacity .28s ease, transform .28s cubic-bezier(.2,.8,.2,1);
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
        }
        body { 
            background: radial-gradient(circle at top center, #0f172a 0%, #07090e 100%); 
            color: #e2e8f0; 
            font-family: 'Courier New', Courier, monospace; 
            margin: 0; 
            padding: 40px; 
            min-height: 100vh;
        }
        .container { 
            max-width: 980px; 
            margin: auto; 
            background: rgba(17, 24, 39, 0.85); 
            backdrop-filter: blur(16px);
            padding: 30px; 
            border-radius: 16px; 
            border: 1px solid rgba(0, 240, 255, 0.15); 
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5); 
        }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1f2937; padding-bottom: 20px; margin-bottom: 20px; }
        .logo-title { display: flex; align-items: center; gap: 12px; }
        .logo-title img { width: 32px; height: 32px; filter: drop-shadow(0 0 8px #00f0ff); }
        h2 { color: #00f0ff; margin: 0; font-weight: 700; text-shadow: 0 0 10px rgba(0,240,255,0.3); }
        .nav-links a { color: #38bdf8; text-decoration: none; margin-left: 15px; font-size: 14px; font-weight: 500; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; background: rgba(11, 15, 25, 0.8); padding: 14px 20px; border-radius: 10px; border: 1px solid #1f2937; margin-bottom: 20px; }
        .tool-buttons { display: flex; gap: 10px; align-items: center; }
        .btn-icon { 
            background: #1f2937; 
            color: #00f0ff; 
            border: 1px solid #374151; 
            padding: 8px 14px; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 14px; 
            font-weight: 600; 
        }
        .btn-icon:hover { background: #00f0ff; color: #07090e; box-shadow: 0 0 15px rgba(0, 240, 255, 0.4); }
        
        .btn-bulk-action { display: none; }
        .btn-bulk-download { background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4); }
        .btn-bulk-download:hover { background: #00f0ff; color: #07090e; }
        .btn-bulk-delete { background: rgba(248, 113, 113, 0.2); color: #f87171; border-color: rgba(248, 113, 113, 0.4); }
        .btn-bulk-delete:hover { background: #f87171; color: #fff; }

        .storage-box { background: rgba(11, 15, 25, 0.8); padding: 18px; border-radius: 10px; border: 1px solid #1f2937; margin-bottom: 25px; }
        .progress-bar { background: #1f2937; border-radius: 6px; height: 14px; width: 100%; margin-top: 10px; overflow: hidden; }
        
        .progress-fill { 
            height: 100%; 
            background-color: {{ bar_color }};
            background-image: linear-gradient(90deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.85) 50%, rgba(255,255,255,0.1) 100%);
            background-size: 200% 100%;
            animation: glowSweep 3s linear infinite;
            box-shadow: 0 0 12px {{ glow_color }};
            border-radius: 6px;
        }
        @keyframes glowSweep {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }

        input[type="checkbox"].item-checkbox {
            appearance: none;
            -webkit-appearance: none;
            width: 18px;
            height: 18px;
            background-color: #07090e;
            border: 1.5px solid #374151;
            border-radius: 4px;
            cursor: pointer;
            position: relative;
            outline: none;
            vertical-align: middle;
            margin-right: 12px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }
        input[type="checkbox"].item-checkbox:hover {
            border-color: #00f0ff;
            box-shadow: 0 0 8px rgba(0, 240, 255, 0.3);
        }
        input[type="checkbox"].item-checkbox:checked {
            background-color: #07090e;
            border-color: #00f0ff;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
        }
        input[type="checkbox"].item-checkbox:checked::after {
            content: '✓';
            color: #00f0ff;
            font-size: 13px;
            font-weight: 900;
            line-height: 1;
        }

        .drop-target-area { 
            border: 2px dashed rgba(0, 240, 255, 0.3); 
            border-radius: 18px; 
            padding: 30px; 
            background: rgba(11, 15, 25, 0.5);
            min-height: max(560px, 62vh);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
        }
        .drop-target-area.drag-over { 
            border-color: #00f0ff !important; 
            background: rgba(0, 240, 255, 0.12) !important; 
            box-shadow: inset 0 0 35px rgba(0, 240, 255, 0.25);
        }
        .empty-box { 
            text-align: center; 
            padding: 120px 28px; 
            min-height: 440px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .drag-overlay { 
            position: fixed; 
            top: 0; left: 0; 
            width: 100%; height: 100%; 
            background: rgba(7, 9, 14, 0.88); 
            backdrop-filter: blur(12px); 
            z-index: 3000; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            pointer-events: none; 
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.5s ease-in-out, visibility 0.5s ease-in-out;
        }
        .drag-overlay.active {
            opacity: 1;
            visibility: visible;
        }
        .drag-overlay-card {
            background: rgba(17, 24, 39, 0.95);
            border: 3px dashed #00f0ff;
            border-radius: 20px;
            padding: clamp(72px, 10vh, 120px) clamp(36px, 6vw, 80px);
            min-height: min(58vh, 560px);
            display: flex;
            flex-direction: column;
            justify-content: center;
            text-align: center;
            box-shadow: 0 0 60px rgba(0, 240, 255, 0.34);
            max-width: 920px;
            width: min(92%, 920px);
            color: #00f0ff;
            transform: scale(0.92);
            transition: transform 0.5s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .drag-overlay.active .drag-overlay-card {
            transform: scale(1);
        }

        ul { list-style: none; padding: 0; margin: 0; width: 100%; }
        li { 
            background: rgba(11, 15, 25, 0.7); 
            padding: 12px 18px; 
            border-radius: 8px; 
            border: 1px solid #1f2937; 
            margin-bottom: 10px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        li:hover { border-color: rgba(0, 240, 255, 0.3); transform: translateX(6px); }
        .file-list-name { display:inline-block; max-width:100%; overflow:hidden; white-space:nowrap; text-overflow:clip; }

        .btn-action, .btn-delete { 
            background: #1f2937; 
            color: #00f0ff; 
            border: 1px solid #374151; 
            padding: 6px 12px; 
            border-radius: 6px; 
            cursor: pointer; 
            font-size: 13px; 
            font-weight: 600; 
        }
        .btn-action:hover { background: #00f0ff; color: #07090e; }
        .btn-preview { color: #a7f3d0; border-color: rgba(167, 243, 208, 0.3); background: rgba(6, 78, 59, 0.4); }
        .btn-preview:hover { background: #10b981; color: #07090e; }
        .btn-delete { color: #f87171; border-color: rgba(248, 113, 113, 0.3); background: rgba(30, 27, 75, 0.6); }
        .btn-delete:hover { background: #f87171; color: #fff; }
        .btn-rename { color: #c4b5fd; border-color: rgba(196, 181, 253, 0.3); background: rgba(76, 29, 149, 0.22); }
        .btn-rename:hover { background: #8b5cf6; color: #fff; }
        .modal-input { box-sizing: border-box; width: 100%; min-width: 0; max-width: 100%; background: #0b0f19; border: 1px solid #374151; color: #fff; padding: 12px 14px; border-radius: 8px; margin: 8px 0 18px; outline: none; font: inherit; }
        .modal-input:focus { border-color: #00f0ff; box-shadow: 0 0 0 3px rgba(0,240,255,.12); }
        /* Keep long names inside the rename dialog instead of letting them widen it. */
        .modal-card { box-sizing: border-box; min-width: 0; max-width: calc(100vw - 32px); overflow-wrap: anywhere; }
        #renameItemText { min-width: 0; max-width: 100%; overflow-wrap: anywhere; word-break: break-word; }
        .btn-icon:focus-visible, .btn-action:focus-visible, .btn-delete:focus-visible { outline: 2px solid #00f0ff; outline-offset: 2px; }

        /* SMOOTH MODAL TRANSITIONS */
        .modal-overlay { 
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
            background: rgba(0, 0, 0, 0.85); z-index: 2000; 
            display: flex; justify-content: center; align-items: center; 
            backdrop-filter: blur(8px); 
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transition: opacity 0.4s ease-in-out, visibility 0.4s ease-in-out, backdrop-filter 0.4s ease-in-out;
        }
        .modal-overlay.active {
            opacity: 1;
            visibility: visible;
            pointer-events: auto;
        }
        .modal-card { 
            background: #111827; 
            border: 1px solid rgba(0, 240, 255, 0.2); 
            border-radius: 14px; 
            width: 500px; 
            padding: 28px;
            transform: translateY(20px) scale(0.95);
            opacity: 0;
            transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s ease-in-out;
        }
        .modal-overlay.active .modal-card {
            transform: translateY(0) scale(1);
            opacity: 1;
        }
        .media-modal-card { width: min(1040px, calc(100vw - 28px)); max-height: 94vh; overflow-y: auto; text-align: left; padding: 20px; background: #0b1020; border: 1px solid rgba(148,163,184,.22); box-shadow: 0 24px 80px rgba(0,0,0,.6); }
        .media-modal-card:fullscreen { width: 100vw; height: 100vh; max-height: 100vh; max-width: 100vw; box-sizing: border-box; border-radius: 0; overflow: auto; }
        .media-modal-card:fullscreen #mediaContainer { flex: 1; }
        .media-modal-card:fullscreen .code-scroll { max-height: calc(100vh - 220px); }
        .media-modal-card:fullscreen .document-stage { height: calc(100vh - 180px); min-height: 55vh; }
        .document-stage { width: 100%; height: min(70vh, 820px); min-height: 360px; overflow: hidden; background: #111827; border: 1px solid #263247; border-radius: 12px; }
        .document-frame { width: 100%; height: 100%; border: 0; background: #fff; }
        .document-info { color: #94a3b8; font-size: 12px; padding: 2px 4px; line-height: 1.5; }
        .code-viewer { width: 100%; min-width: 0; overflow: hidden; border: 1px solid #263247; border-radius: 12px; background: #0b1020; }
        .code-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 10px; background: linear-gradient(145deg,#151e30,#0d1422); border-bottom: 1px solid #263247; }
        .code-toolbar .code-meta { color: #8ea0b8; font: 12px 'Courier New', monospace; margin-right: auto; }
        .code-select { color: #e2e8f0; background: #0a111d; border: 1px solid #334155; padding: 7px 9px; border-radius: 8px; font: inherit; }
        .code-toggle-btn { color: #aab8cc; background: #0a111d; border: 1px solid #334155; padding: 7px 10px; border-radius: 8px; font: inherit; cursor: pointer; transition: background .15s ease, border-color .15s ease, color .15s ease; }
        .code-toggle-btn[aria-pressed="true"] { color: #06121b; background: #00e5ff; border-color: #00e5ff; box-shadow: 0 0 0 2px rgba(0,229,255,.16); }
        .code-toggle-btn:focus-visible { outline: 2px solid #67e8f9; outline-offset: 2px; }
        .code-wrap-toggle { display: inline-flex; align-items: center; gap: 2px; padding: 5px 9px; border: 1px solid #334155; border-radius: 8px; background: #0a111d; color: #dbeafe; cursor: pointer; user-select: none; white-space: nowrap; }
        .code-wrap-toggle:hover { border-color: #00f0ff; box-shadow: 0 0 10px rgba(0,240,255,.12); }
        .code-wrap-toggle .item-checkbox { flex: 0 0 auto; margin: 0 7px 0 0; }
        .code-viewer[data-theme="light"] .code-wrap-toggle { background: #fff; color: #1e293b; border-color: #cbd5e1; }
        .code-viewer[data-theme="light"] .code-wrap-toggle .item-checkbox { background: #f8fafc; }
        #mediaContainer:fullscreen { width: 100vw; height: 100vh; max-width: 100vw; max-height: 100vh; box-sizing: border-box; overflow: auto; border: 0; border-radius: 0; padding: clamp(12px, 3vw, 32px) !important; justify-content: center; background: #070b13 !important; }
        #mediaContainer:fullscreen .media-stage { width: 100%; }
        #mediaContainer:fullscreen .media-player-video { width: 100%; max-height: 58vh; }
        #mediaContainer:fullscreen .media-control-panel { width: min(100%, 1100px); align-self: center; flex-shrink: 0; }
        .code-scroll { max-height: min(65vh, 760px); overflow: auto; background: #0b1020; color: #dbeafe; }
        .code-lines { display: grid; grid-template-columns: auto max-content; width: max-content; min-width: max-content; font: 13px/1.65 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; tab-size: 4; }
        .code-lines.wrap { display: grid; grid-template-columns: auto minmax(0, 1fr); width: 100% !important; min-width: 0 !important; max-width: 100%; }
        .code-lines.wrap .code-source { display: block; min-width: 0 !important; width: 100% !important; max-width: 100%; box-sizing: border-box; white-space: pre-wrap !important; overflow-wrap: anywhere; word-break: normal; }
        .code-scroll:has(.code-lines.wrap) { overflow-x: hidden; }
        .code-scroll:has(.code-lines:not(.wrap)) { overflow-x: auto; }
        .code-wrap-toggle[aria-pressed="true"] { color: #06121b; background: #00e5ff; border-color: #00e5ff; box-shadow: 0 0 0 2px rgba(0,229,255,.16); }
        .code-viewer[data-theme="light"] .code-wrap-toggle[aria-pressed="true"] { color: #06121b; background: #67e8f9; border-color: #0891b2; }
        .code-gutter { color: #64748b; text-align: right; user-select: none; padding: 14px 12px 14px 14px; border-right: 1px solid #263247; background: rgba(2,6,23,.45); white-space: pre; }
        .code-source { margin: 0; padding: 14px 18px; white-space: pre; color: inherit; }
        .code-source.wrap { white-space: pre-wrap; overflow-wrap: anywhere; }
        .code-viewer[data-theme="monokai"] { background: #272822; }
        .code-viewer[data-theme="monokai"] .code-scroll, .code-viewer[data-theme="monokai"] .code-gutter { background: #272822; }
        .code-viewer[data-theme="monokai"] .code-gutter { border-color: #49483e; color: #75715e; }
        .code-viewer[data-theme="light"] { background: #f8fafc; color: #1e293b; }
        .code-viewer[data-theme="light"] .code-scroll, .code-viewer[data-theme="light"] .code-gutter { background: #f8fafc; color: #1e293b; }
        .code-viewer[data-theme="light"] .code-toolbar { background: #e2e8f0; border-color: #cbd5e1; }
        .code-viewer[data-theme="light"] .code-meta { color: #475569; }
        .code-viewer[data-theme="light"] .code-select { background: white; color: #1e293b; border-color: #cbd5e1; }
        .tok-comment { color: #8292a2; font-style: italic; }
        .tok-string { color: #a5e075; }
        .tok-keyword { color: #c792ea; font-weight: 600; }
        .tok-number { color: #f78c6c; }
        .tok-function { color: #82aaff; }
        .tok-type { color: #ffcb6b; }
        .tok-operator { color: #89ddff; }
        .code-viewer[data-theme="monokai"] .tok-comment { color: #75715e; }
        .code-viewer[data-theme="monokai"] .tok-string { color: #e6db74; }
        .code-viewer[data-theme="monokai"] .tok-keyword { color: #f92672; }
        .code-viewer[data-theme="monokai"] .tok-number { color: #ae81ff; }
        .code-viewer[data-theme="monokai"] .tok-function { color: #a6e22e; }
        .code-viewer[data-theme="monokai"] .tok-type { color: #66d9ef; }
        .code-viewer[data-theme="light"] .tok-comment { color: #64748b; }
        .code-viewer[data-theme="light"] .tok-string { color: #15803d; }
        .code-viewer[data-theme="light"] .tok-keyword { color: #7e22ce; }
        .code-viewer[data-theme="light"] .tok-number { color: #c2410c; }
        .code-viewer[data-theme="light"] .tok-function { color: #1d4ed8; }
        .code-viewer[data-theme="light"] .tok-type { color: #a16207; }
        .code-viewer[data-theme="light"] .tok-operator { color: #0369a1; }
        .code-info { color: #94a3b8; font-size: 12px; padding: 8px 4px 2px; line-height: 1.5; }
        .media-title-actions { display: flex; align-items: center; gap: 10px; }
        .media-modal-card h3 { align-items: center; gap: 16px; color: #e2e8f0 !important; font-size: 15px; letter-spacing: .2px; }
        #mediaTitleText { min-width: 0; overflow-wrap: anywhere; }
        #mediaContainer { min-height: 0 !important; background: #070b13 !important; border: 1px solid #202a3a; border-radius: 16px !important; padding: clamp(10px, 2vw, 18px) !important; gap: 12px; }
        .media-stage { position: relative; width: 100%; min-height: 180px; overflow: hidden; display: flex; justify-content: center; align-items: center; background: #020308; border-radius: 12px; }
        .video-center-play { position: absolute; z-index: 4; left: 50%; top: 50%; transform: translate(-50%, -50%); width: 78px; height: 78px; border-radius: 50%; border: 2px solid rgba(255,255,255,.9); background: rgba(3,10,20,.78); color: #67e8f9; font-size: 30px; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 0 28px rgba(0,240,255,.28); backdrop-filter: blur(6px); }
        .video-center-play:hover { background: rgba(0,229,255,.92); color: #06111c; transform: translate(-50%, -50%) scale(1.08); }
        .video-center-play.is-hidden { opacity: 0; visibility: hidden; pointer-events: none; }
        #mediaContainer:fullscreen .media-stage { flex: 1 1 auto; min-height: 0; max-height: calc(100vh - 190px); }
        #mediaContainer:fullscreen .media-player-video { max-height: calc(100vh - 220px); }
        #mediaContainer:fullscreen .media-control-panel { flex: 0 0 auto; }
        .media-player-video { display: block; width: 100%; max-width: 100%; max-height: min(62vh, 720px); height: auto; object-fit: contain; background: #000; border-radius: 12px; }
        /* Video fullscreen is video-only: no modal header, empty padding, or oversized custom panel. */
        .media-player-video:fullscreen { width: 100vw !important; height: 100vh !important; max-width: 100vw !important; max-height: 100vh !important; object-fit: contain; background: #000 !important; border-radius: 0 !important; }
        .media-player-video::-webkit-media-controls { display: flex !important; }
        .media-control-panel { width: 100%; padding: 13px; background: linear-gradient(145deg, #151e30, #0d1422); border: 1px solid #263247; border-radius: 12px; display: flex; flex-direction: column; gap: 10px; }
        .media-control-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .media-control-btn { border: 1px solid #334155; color: #e2e8f0; background: #182338; border-radius: 8px; padding: 8px 11px; min-height: 36px; cursor: pointer; font: inherit; }
        .media-control-btn:hover { background: #23334c; border-color: #38bdf8; }
        .media-control-btn.primary { color: #06111c; background: #67e8f9; border-color: #67e8f9; font-weight: 700; min-width: 44px; }
        .media-control-btn:focus-visible, .media-select:focus-visible, .media-seek:focus-visible { outline: 2px solid #67e8f9; outline-offset: 2px; }
        .media-seek { width: 100%; accent-color: #67e8f9; cursor: pointer; }
        .media-time-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; color: #aab8cc; font: 12px 'Courier New', monospace; }
        .media-select { color: #e2e8f0; background: #0a111d; border: 1px solid #334155; padding: 8px 10px; border-radius: 8px; max-width: 100%; font: inherit; }
        .media-setting { display: flex; align-items: center; gap: 7px; color: #aebdd0; font-size: 12px; }
        .media-setting span { white-space: nowrap; }
        .audio-artwork { min-height: 190px; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 13px; text-align: center; padding: 24px; border-radius: 12px; background: radial-gradient(circle at 50% 0%, rgba(103,232,249,.16), transparent 60%), linear-gradient(145deg,#111b2e,#080c15); }
        .audio-disc { width: 92px; height: 92px; border-radius: 50%; display: grid; place-items: center; color: #67e8f9; border: 1px solid rgba(103,232,249,.4); background: repeating-radial-gradient(circle,#17263a 0 4px,#0c1422 5px 8px); box-shadow: 0 0 32px rgba(34,211,238,.1); font-size: 32px; }
        .audio-disc.playing { animation: audio-spin 7s linear infinite; }
        @keyframes audio-spin { to { transform: rotate(360deg); } }
        .audio-file-name { color: #f1f5f9; font-size: 15px; font-weight: 700; overflow-wrap: anywhere; }
        .photo-stage { min-height: 200px; max-height: 70vh; overflow: auto; display: flex; align-items: center; justify-content: center; background: repeating-conic-gradient(#0d1420 0% 25%, #080d16 0% 50%) 50% / 24px 24px; border-radius: 12px; }
        .photo-viewer-image { max-width: 100%; max-height: 68vh; object-fit: contain; transition: transform .15s ease; }
        .media-close-row { margin-top: 14px !important; padding-top: 12px; border-top: 1px solid #202a3a; }
        @media (max-width: 600px) { .media-modal-card { padding: 12px; width: calc(100vw - 12px); } .media-control-panel { padding: 9px; } .media-control-row { gap: 6px; } .media-control-btn { padding: 7px 9px; } .media-setting { flex: 1 1 140px; } .media-select { min-width: 0; flex: 1; } }

        .dir-picker-box {
            background: #0b0f19;
            border: 1px solid #1f2937;
            border-radius: 10px;
            max-height: 280px;
            overflow-y: auto;
            margin: 15px 0;
            padding: 8px;
        }
        .dir-picker-item {
            padding: 10px 14px;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            border: 1px solid transparent;
            margin-bottom: 6px;
            transition: all 0.3s ease;
        }
        .dir-picker-item:hover {
            background: rgba(0, 240, 255, 0.1);
            border-color: rgba(0, 240, 255, 0.3);
            color: #00f0ff;
        }

        input[type="text"] { background: #0b0f19; border: 1px solid #374151; color: #fff; padding: 10px; border-radius: 8px; width: 100%; margin-bottom: 15px; outline: none; }

        /* SMOOTH TRANSFER MANAGER WIDGET */
        #transferQueue { 
            position: fixed; bottom: 30px; right: 30px; width: 360px; 
            background: rgba(17, 24, 39, 0.95); backdrop-filter: blur(12px); 
            border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 12px; 
            box-shadow: 0 15px 35px rgba(0,0,0,0.6); z-index: 2500; overflow: hidden; 
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transform: translateY(20px) scale(0.95);
            transition: opacity 0.5s ease-in-out, transform 0.5s cubic-bezier(0.16, 1, 0.3, 1), visibility 0.5s ease-in-out;
        }
        #transferQueue.active {
            opacity: 1;
            visibility: visible;
            pointer-events: auto;
            transform: translateY(0) scale(1);
        }
        .queue-header { background: #0b0f19; padding: 12px 16px; font-size: 13px; font-weight: bold; color: #00f0ff; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center; }
        .queue-body { max-height: 240px; overflow-y: auto; padding: 12px; }
        .transfer-item { 
            background: #0b0f19; padding: 10px 12px; border-radius: 8px; margin-bottom: 10px; font-size: 12px; border: 1px solid #1f2937; 
            transition: opacity 0.6s ease-in-out, transform 0.6s ease-in-out, max-height 0.6s ease-in-out, margin 0.6s ease-in-out, padding 0.6s ease-in-out;
            max-height: 80px; opacity: 1; transform: translateY(0);
        }
        .transfer-item.fading-out { opacity: 0; transform: translateY(12px); max-height: 0; margin-bottom: 0; padding-top: 0; padding-bottom: 0; overflow: hidden; border-color: transparent; }
        .transfer-info { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; color: #94a3b8; }
        .transfer-bar-bg { background: #1f2937; border-radius: 4px; height: 6px; width: 100%; overflow: hidden; }
        .transfer-bar-fill { background: linear-gradient(90deg, #00f0ff, #10b981); height: 100%; width: 0%; transition: width 0.4s ease-out; }
    </style>
</head>
<body>

    <div id="dragDropOverlay" class="drag-overlay">
        <div class="drag-overlay-card">
            <span style="font-size: 64px; display: block; margin-bottom: 15px;">📥</span>
            <div style="font-size: 24px; font-weight: bold; margin-bottom: 8px;">Drop Files Here to Upload</div>
            <div style="color: #94a3b8; font-size: 15px;">Uploading directly into <u>{{ folder_title }}</u></div>
        </div>
    </div>

    <div id="transferQueue">
        <div class="queue-header"><span><span aria-hidden="true" style="color:#facc15; -webkit-text-fill-color:#facc15;">⚡</span> Active Transfer Manager</span></div>
        <div class="queue-body" id="queueList"></div>
    </div>
    <div id="transferHistoryDialog" class="modal-overlay" style="z-index:6100;display:none;align-items:center;justify-content:center;">
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="transferHistoryTitle" style="width:min(1120px,94vw);max-width:1120px;max-height:84vh;overflow:hidden;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;border-bottom:1px solid #263448;padding-bottom:12px;">
          <div><h3 id="transferHistoryTitle" style="margin:0;color:#00f0ff;">Transfer Manager history</h3><p style="margin:5px 0 0;color:#94a3b8;">Your account's recent transfers · last 10 days</p></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap"><button type="button" class="btn-icon" id="clearTransferHistory" style="border-color:#7f1d1d;color:#fecaca;">Clear log</button><button type="button" class="btn-icon" id="closeTransferHistory">✕ Close</button></div>
        </div>
        <div id="transferHistoryList" style="overflow:auto;padding-top:10px;min-height:180px;">Loading transfer history…</div>
      </div>
    </div>
    <div id="uploadLeaveDialog" class="modal-overlay" style="z-index:6000;display:none;align-items:center;justify-content:center;">
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="uploadLeaveTitle" style="width:min(520px,94vw);">
        <h3 id="uploadLeaveTitle" style="color:#fbbf24;margin-top:0;">Upload in progress</h3>
        <p id="uploadLeaveMessage" style="color:#cbd5e1;line-height:1.6;">Are you sure you want to leave? The active upload will be cancelled if you continue.</p>
        <div style="display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap;margin-top:18px;">
          <button type="button" class="btn-icon" id="stayUploadingBtn">Stay on this page</button>
          <button type="button" class="btn-icon" id="forceLeaveUploadingBtn" style="background:#b91c1c;color:white;border-color:#ef4444;">Force quit &amp; cancel upload</button>
        </div>
      </div>
    </div>

    <div id="mediaModal" class="modal-overlay">
        <div class="modal-card media-modal-card">
            <h3 style="color:#00f0ff; display:flex; justify-content:space-between; margin-top:0;">
                <span id="mediaTitleText">Media Viewer</span>
                <span class="media-title-actions"><button type="button" class="media-control-btn" id="btnMediaFullscreen" aria-label="Toggle full screen">⛶ Full screen</button><button type="button" id="btnCloseMediaTop" style="background:none; border:none; color:#f87171; font-size:20px; cursor:pointer;" aria-label="Close viewer">✕</button></span>
            </h3>
            <div id="mediaContainer" style="display:flex; flex-direction:column; justify-content:center; align-items:stretch;"></div>
            <div class="media-close-row" style="text-align:right;">
                <button type="button" class="btn-icon" id="btnCloseMediaBottom">Close Media Viewer</button>
            </div>
        </div>
    </div>

    <div id="dirPickerModal" class="modal-overlay" style="z-index: 2200;">
        <div class="modal-card" style="width: 520px;">
            <h3 style="color:#00f0ff; margin-top:0;">📁 Select Target Directory</h3>
            <div id="dirPickerPathText" style="font-size: 13px; color: #38bdf8; font-weight: 600; margin-bottom: 8px;">Location: {{ user_folder_name }}</div>
            
            <div class="dir-picker-box" id="dirPickerList"></div>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:15px;">
                <button type="button" class="btn-icon" onclick="closeDirPickerModal()" style="background:#374151; color:#fff;">Cancel</button>
                <button type="button" class="btn-icon" onclick="confirmSelectedDir()" style="background:#00f0ff; color:#07090e; border:none;">✅ Select This Directory</button>
            </div>
        </div>
    </div>

    <div id="uploadModal" class="modal-overlay">
        <div class="modal-card">
            <h3 style="color:#00f0ff; margin-top:0;">📤 Confirm Upload</h3>
            <p id="uploadFileInfo" style="color:#e2e8f0; font-size:14px;">Selected files: none</p>
            
            <div style="background: rgba(11, 15, 25, 0.8); padding: 12px; border-radius: 8px; border: 1px solid #1f2937; margin-bottom: 18px;">
                <label style="color:#94a3b8; font-size:12px; display:block; margin-bottom:4px;">TARGET DIRECTORY:</label>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span id="targetDirDisplay" style="color:#00f0ff; font-weight:bold; font-size:14px;">{{ user_folder_name }}</span>
                    <button type="button" class="btn-icon" onclick="openDirPickerModal(selectedTargetRelPath)" style="font-size:12px; padding:5px 10px;">📁 Browse / Change Folder</button>
                </div>
            </div>

            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button type="button" class="btn-icon" id="btnCancelUpload" style="background:#374151; color:#fff;">Cancel</button>
                <button type="button" class="btn-icon" id="btnExecuteUpload">Confirm Upload</button>
            </div>
        </div>
    </div>

    <div id="folderModal" class="modal-overlay">
        <div class="modal-card">
            <h3 style="color:#00f0ff; margin-top:0;">📁 Create New Folder</h3>
            <input class="modal-input" type="text" id="newFolderNameInput" placeholder="Folder name" autocomplete="off" data-autofocus>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button type="button" class="btn-icon" id="btnCancelFolder" style="background:#374151; color:#fff;">Cancel</button>
                <button type="button" class="btn-icon" id="btnExecuteFolder">Create</button>
            </div>
        </div>
    </div>

    <div id="renameModal" class="modal-overlay">
        <div class="modal-card">
            <h3 style="color:#c4b5fd; margin-top:0;">✏️ Rename File or Folder</h3>
            <p id="renameItemText" style="color:#94a3b8; margin:0 0 8px;"></p>
            <input class="modal-input" type="text" id="renameItemNameInput" placeholder="Enter a new name" autocomplete="off" data-autofocus>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button type="button" class="btn-icon" id="btnCancelRename" style="background:#374151; color:#fff;">Cancel</button>
                <button type="button" class="btn-icon" id="btnExecuteRename">Confirm Rename</button>
            </div>
        </div>
    </div>

    <div id="deleteModal" class="modal-overlay">
        <div class="modal-card">
            <h3 style="color:#f87171; margin-top:0;">🗑️ Confirm Deletion</h3>
            <p id="deleteItemText">Are you sure you want to delete selected items?</p>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button type="button" class="btn-icon" id="btnCancelDelete" style="background:#374151; color:#fff;">Cancel</button>
                <button type="button" class="btn-icon" id="btnExecuteDelete" style="background:#f87171; color:#fff;">Delete</button>
            </div>
        </div>
    </div>


    <div id="accountBackdrop" class="account-backdrop" aria-hidden="true"></div>
    <aside id="accountDrawer" class="account-drawer" aria-label="Account settings" aria-hidden="true">
        <div class="account-drawer-head">
            <div><div class="account-eyebrow">CYBER DRIVE</div><h3>Account menu</h3></div>
            <button type="button" id="closeAccountMenu" class="account-close" aria-label="Close menu">✕</button>
        </div>
        <div class="account-profile">
            <div class="account-avatar">☁</div>
            <div style="min-width:0"><strong id="menuDisplayName">{{ account_display_name or 'My Drive' }}</strong><div class="account-muted" id="menuEmail">{{ account_email or 'Email not set' }}</div></div>
        </div>
        <nav class="account-nav">
            <button type="button" data-account-panel="profile">👤 <span>Profile & linked accounts</span></button>
            <button type="button" data-account-panel="security">🔐 <span>Password & recovery</span></button>
            <button type="button" data-account-panel="storage">💾 <span>Storage & expansion</span></button>
            <button type="button" data-account-panel="activity">🕘 <span>Login activity</span></button>
            <button type="button" data-account-panel="delete">🗑️ <span>Delete account</span></button>
        </nav>
        <section class="account-panel" id="panel-profile">
            <h4>Profile settings</h4>
            <div class="account-form">
                <label>Display name</label>
                <div class="account-muted" id="currentDisplayName">{{ account_display_name or 'My Drive' }}</div>
                <button type="button" class="account-primary" onclick="document.getElementById('changeNameDialog').showModal()">Change name</button>
                <label>Email address</label>
                <div class="account-muted" id="currentAccountEmail">{{ account_email or 'Email not set' }}</div>
                <button type="button" class="account-primary" onclick="document.getElementById('changeEmailDialog').showModal()">Change email</button>
            </div>
            <dialog id="changeNameDialog" class="account-dialog">
                <form method="post" action="/account/profile" class="account-form">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                    <h4>Change display name</h4>
                    <label>New display name / home folder name</label>
                    <input name="display_name" value="{{ account_display_name or '' }}" maxlength="60" required autocomplete="name">
                    <div class="dialog-actions"><button type="button" class="account-secondary" onclick="document.getElementById('changeNameDialog').close()">Cancel</button><button class="account-primary" type="submit">Save name</button></div>
                </form>
            </dialog>
            <dialog id="changeEmailDialog" class="account-dialog">
                <form method="post" action="/account/email-change/request" class="account-form">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                    <h4>Change email address</h4>
                    <p class="account-muted">Only @iith.ac.in addresses are accepted. Your current email stays active until the new address is verified.</p>
                    <label>New institutional email</label>
                    <input type="email" name="new_email" placeholder="you@iith.ac.in" pattern=".+@iith\.ac\.in" required autocomplete="email">
                    <div class="dialog-actions"><button type="button" class="account-secondary" onclick="document.getElementById('changeEmailDialog').close()">Cancel</button><button class="account-primary" type="submit">Send verification code</button></div>
                </form>
            </dialog>
            <style>
              .account-dialog{width:min(420px,90vw);border:1px solid #334155;border-radius:14px;background:#0b1220;color:#e2e8f0;padding:20px;box-shadow:0 20px 70px #0009}
              .account-dialog::backdrop{background:#020617b8;backdrop-filter:blur(4px)}
              .account-dialog h4{margin:0 0 8px;color:#67e8f9}.dialog-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:10px}.dialog-actions button{width:auto;flex:1}
            </style>
            <div class="account-provider"><p class="account-muted">Google login not available.</p></div>
        </section>
        <section class="account-panel" id="panel-security" hidden>
            <h4>Security</h4>
            <form method="post" action="/account/change-password" class="account-form">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                <label>Current password</label><input type="password" name="current_password" autocomplete="current-password">
                <label>New password</label><input type="password" name="new_password" minlength="10" autocomplete="new-password">
                <label>Confirm new password</label><input type="password" name="confirm_password" minlength="10" autocomplete="new-password">
                <button class="account-primary" type="submit">Change password</button>
            </form>
            <a class="account-secondary account-link" href="/forgot-password">Forgot password / email OTP</a>
        </section>
        <section class="account-panel" id="panel-storage" hidden>
            <h4>Storage &amp; expansion</h4>
            <p class="account-muted">Current allocation: <strong>{{ quota_gb }} GB</strong> · Maximum total allocation: <strong>10 GB</strong>.</p>
            <p class="account-muted">You may request an increase or decrease of 1–3 GB at a time. Your final allocation must remain between 1 GB and 10 GB, and a decrease cannot take your quota below the space already used. Only one request can be pending at a time.</p>
            {% if storage_request_pending %}
              <div class="account-muted" style="padding:10px;border:1px solid #155e75;border-radius:8px;background:#083344;color:#a5f3fc;">Your storage change request is pending admin review.</div>
            {% else %}
              <form method="post" action="/storage/request" class="account-form" style="margin-top:12px;">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                <label for="storage_request_type">Request type</label>
                <select id="storage_request_type" name="request_type" required style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;background:#070b13;color:#e2e8f0;border:1px solid #334155;">
                  <option value="increase">Increase my allocation</option><option value="decrease">Decrease my allocation</option>
                </select>
                <label for="additional_gb">Amount (1–3 GB)</label>
                <select id="additional_gb" name="additional_gb" required style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;background:#070b13;color:#e2e8f0;border:1px solid #334155;">
                  {% for n in range(1, 4) %}<option value="{{ n }}">{{ n }} GB</option>{% endfor %}
                </select>
                <label for="storage_reason">Reason (10–1000 characters)</label>
                <textarea id="storage_reason" name="reason" minlength="10" maxlength="1000" required rows="3" placeholder="Explain why you need this storage change" style="width:100%;box-sizing:border-box;padding:10px;border-radius:8px;background:#070b13;color:#e2e8f0;border:1px solid #334155;font:inherit;"></textarea>
                <p id="storageLimitNotice" class="account-muted" role="status" style="padding:10px;border:1px solid #334155;border-radius:8px;"></p>
                <button id="storageRequestButton" class="account-primary" type="submit">Submit storage request</button>
                <script>(function(){let current={{ quota_gb|int }};const used={{ used_gb|round(2) }};const type=document.getElementById('storage_request_type');const amount=document.getElementById('additional_gb');const note=document.getElementById('storageLimitNotice');const button=document.getElementById('storageRequestButton');function update(){const n=Number(amount.value||0),increase=type.value==='increase',total=current+(increase?n:-n);let msg='After approval, your allocation would be '+total+' GB total.';let invalid=false;if(increase&&total>10){msg='This request cannot be sent: Cyber Drive currently serves a maximum of 10 GB per user.';invalid=true;}else if(!increase&&total<1){msg='The minimum allocation is 1 GB.';invalid=true;}else if(!increase&&total<used){msg='This decrease cannot be requested because you are already using '+used.toFixed(2)+' GB.';invalid=true;}note.textContent=msg;note.style.borderColor=invalid?'#f87171':'#155e75';note.style.color=invalid?'#fca5a5':'#a5f3fc';button.disabled=invalid;button.title=invalid?'Storage limit would be violated':'Submit storage request';}type.addEventListener('change',update);amount.addEventListener('change',update);update();window.updateStorageRequestQuota=function(next){current=Number(next)||current;update();};})();</script>
              </form>
            {% endif %}
        </section>
        <section class="account-panel" id="panel-activity" hidden>
            <h4>Account activity</h4>
            <p class="account-muted">Account, storage, upload, and download events from the last 10 days.</p>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0"><button type="button" class="account-primary" id="clearSessionActivity">Clear my log</button><button type="button" class="account-secondary" id="openTransferHistory">Transfer Manager history</button></div>
            <div id="sessionActivityList" class="activity-list">Open this panel to load activity.</div>
        </section>
        <section class="account-panel" id="panel-delete" hidden>
            <h4 style="color:#f87171">Delete account</h4>
            <p class="account-muted">Permanently deletes this account and its Cyber Drive files. This cannot be undone.</p>
            <form method="post" action="/account/delete" class="account-form" onsubmit="return confirm('Permanently delete your account and all its stored files? This cannot be undone.');">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                <label>Confirm account email</label><input type="email" name="confirm_email" required autocomplete="email" value="{{ account_email or '' }}">
                <label>Current password</label><input type="password" name="current_password" autocomplete="current-password" placeholder="Required for password accounts">
                <label>Type DELETE to confirm</label><input name="delete_confirmation" required pattern="DELETE" autocomplete="off">
                <button class="account-primary" type="submit" style="background:#7f1d1d;color:#fff;border-color:#ef4444">Permanently delete account</button>
            </form>
        </section>
        <div class="account-drawer-foot"><a href="/logout">↪ Log out</a></div>
    </aside>
    <style>
      .header {gap:14px}
      .account-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.48);backdrop-filter:blur(9px);z-index:4000;opacity:0;visibility:hidden;transition:opacity .28s ease,visibility .28s ease}
      .account-backdrop.active{opacity:1;visibility:visible}
      .account-drawer{position:fixed;z-index:4001;top:0;left:0;height:100dvh;width:min(390px,92vw);padding:22px;background:rgba(10,16,29,.97);border-right:1px solid rgba(0,240,255,.25);box-shadow:18px 0 60px rgba(0,0,0,.45);backdrop-filter:blur(20px);transform:translateX(-105%);transition:transform .38s cubic-bezier(.16,1,.3,1);overflow-y:auto;display:flex;flex-direction:column;gap:18px}
      .account-drawer.active{transform:translateX(0)}
      .account-drawer-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
      .account-drawer-head h3{color:#e2e8f0;margin:4px 0;font-size:21px}.account-eyebrow{color:#00f0ff;font-size:10px;letter-spacing:2px}
      .account-close{background:#1f2937;border:1px solid #374151;color:#e2e8f0;border-radius:9px;padding:8px 11px;cursor:pointer}
      .account-profile{display:flex;align-items:center;gap:12px;padding:14px;background:#0b1220;border:1px solid #263247;border-radius:13px;min-width:0}
      .account-avatar{width:42px;height:42px;display:grid;place-items:center;flex:0 0 auto;background:rgba(0,240,255,.12);border:1px solid rgba(0,240,255,.35);border-radius:12px;color:#00f0ff;font-size:23px}
      #menuDisplayName{display:block;overflow-wrap:anywhere}.account-muted{color:#94a3b8;font-size:12px;line-height:1.5;overflow-wrap:anywhere}
      .account-nav{display:grid;gap:7px}.account-nav button{display:flex;gap:10px;align-items:center;text-align:left;background:transparent;border:1px solid transparent;color:#cbd5e1;padding:12px;border-radius:9px;cursor:pointer}.account-nav button:hover,.account-nav button.selected{background:rgba(0,240,255,.08);border-color:rgba(0,240,255,.2);color:#67e8f9}
      .account-panel{padding:15px;background:#0b1220;border:1px solid #263247;border-radius:12px}.account-panel h4{margin:0 0 14px;color:#67e8f9}
      .account-form{display:grid;gap:8px}.account-form label{font-size:11px;color:#94a3b8;margin-top:5px}.account-form input{width:100%;min-width:0;box-sizing:border-box;background:#070b13;color:#e2e8f0;border:1px solid #334155;border-radius:8px;padding:10px;font:inherit;font-size:13px}
      .account-primary,.account-secondary{display:block;text-align:center;width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;text-decoration:none;cursor:pointer;font:inherit;font-size:12px;margin-top:9px}
      .account-primary{background:#00e5ff;border:1px solid #00e5ff;color:#06111c;font-weight:bold}.account-secondary{background:#1f2937;border:1px solid #374151;color:#cbd5e1}
      .account-provider{border-top:1px solid #263247;margin-top:15px;padding-top:10px}.account-link{margin-top:8px}
      .account-drawer-foot{margin-top:auto;border-top:1px solid #263247;padding-top:14px}.account-drawer-foot a{color:#f87171;text-decoration:none}
      .activity-list{display:grid;gap:8px}.activity-row{padding:10px;background:#070b13;border:1px solid #263247;border-radius:8px;font-size:12px}.activity-row strong{display:block;color:#67e8f9;margin-bottom:3px}.activity-row span{color:#94a3b8}
      @media(max-width:600px){body{padding:12px}.container{padding:14px}.header{flex-wrap:wrap}.account-drawer{padding:16px}}
    </style>
    <script>
    document.addEventListener('DOMContentLoaded', function(){
      const drawer=document.getElementById('accountDrawer'),backdrop=document.getElementById('accountBackdrop');
      const openBtn=document.getElementById('openAccountMenu'),closeBtn=document.getElementById('closeAccountMenu');
      function openMenu(){if(!drawer||!backdrop)return;drawer.classList.add('active');backdrop.classList.add('active');drawer.setAttribute('aria-hidden','false');backdrop.setAttribute('aria-hidden','false');document.body.style.overflow='hidden'}
      function closeMenu(){if(!drawer||!backdrop)return;drawer.classList.remove('active');backdrop.classList.remove('active');drawer.setAttribute('aria-hidden','true');backdrop.setAttribute('aria-hidden','true');document.body.style.overflow=''}
      openBtn?.addEventListener('click',openMenu);closeBtn?.addEventListener('click',closeMenu);backdrop?.addEventListener('click',closeMenu);
      document.addEventListener('keydown',e=>{if(e.key==='Escape')closeMenu()});
      const navButtons=[...document.querySelectorAll('[data-account-panel]')];
      navButtons.forEach(btn=>btn.addEventListener('click',()=>{
        navButtons.forEach(b=>b.classList.toggle('selected',b===btn));
        document.querySelectorAll('.account-panel').forEach(p=>p.hidden=p.id!=='panel-'+btn.dataset.accountPanel);
        if(btn.dataset.accountPanel==='activity')loadActivity();
      }));
      async function loadActivity(){
        const target=document.getElementById('sessionActivityList');target.textContent='Loading activity…';
        try{const r=await fetch('/api/session-activity',{headers:{'Accept':'application/json'}});const data=await r.json();
          target.replaceChildren();
          if(!r.ok)throw new Error(data.error||'Unable to load activity');
          if(!data.events.length){target.textContent='No account activity in the last 10 days.';return}
          data.events.forEach(ev=>{const row=document.createElement('div');row.className='activity-row';const strong=document.createElement('strong');const labels={login:'✓ Login',logout:'↪ Logout',upload:'⬆ Upload',download:'⬇ Download',storage_allocation:'☁ Storage allocation',storage_request:'☁ Storage request'};strong.textContent=labels[ev.event]||('• '+ev.event.replaceAll('_',' '));const span=document.createElement('span');span.textContent=ev.time+' · '+ev.method;row.append(strong,span);target.append(row)});
        }catch(e){target.textContent='Could not load activity.'}
      }
      document.getElementById('clearSessionActivity')?.addEventListener('click',async()=>{
        if(!confirm('Clear your login activity log? This only clears the activity history, not your account.'))return;
        const target=document.getElementById('sessionActivityList');
        try{const token=document.querySelector('meta[name=csrf-token]')?.content||'';const r=await fetch('/api/session-activity/clear',{method:'POST',headers:{'X-CSRF-Token':token,'Accept':'application/json'}});const data=await r.json();if(!r.ok)throw new Error(data.error||'Could not clear log');await loadActivity();}
        catch(e){target.textContent=e.message||'Could not clear log.'}
      });
      navButtons.find(b=>b.dataset.accountPanel==='profile')?.classList.add('selected');
      document.querySelectorAll('.account-panel').forEach(p=>p.hidden=p.id!=='panel-profile');
    });
    </script>

    <input type="file" id="hiddenFileInput" style="display:none;" multiple>

    <div class="container">
        <div class="header">
            <button type="button" id="openAccountMenu" class="btn-icon" aria-label="Open account menu" title="Account menu" style="font-size:22px;padding:8px 12px;line-height:1;">☰</button>
            <div class="logo-title">
                <img src="/cloud-icon.svg?v=3" alt="Cyber Drive Logo">
                <h2>Cyber Drive — {{ account_display_name or 'My Drive' }}</h2>
            </div>
            <div class="nav-links">
                <a href="/files/">🏠 {{ user_folder_name }}</a>
                <a href="/logout" style="color:#f87171;">Logout</a>
            </div>
        </div>

        {% with notices = get_flashed_messages() %}
        {% if notices %}<div class="cd-transient-notice" role="status" aria-live="polite" style="margin-bottom:16px;padding:12px;border:1px solid rgba(0,240,255,.25);border-radius:9px;background:rgba(0,240,255,.07);color:#a5f3fc;transition:opacity .35s ease,transform .35s ease;">{% for notice in notices %}<div>{{ notice }}</div>{% endfor %}</div>{% endif %}
        {% endwith %}
        {% if error_msg %}
        <div class="cd-transient-notice" role="alert" style="color:#f87171; padding:10px; background:rgba(248,113,113,0.1); border-radius:8px; margin-bottom:15px;transition:opacity .35s ease,transform .35s ease;">{{ error_msg }}</div>
        {% endif %}
        <script>(function(){document.querySelectorAll('.cd-transient-notice').forEach(function(el){var timer=setTimeout(function(){el.style.opacity='0';el.style.transform='translateY(-5px)';setTimeout(function(){el.remove()},400)},5000);el.addEventListener('click',function(){clearTimeout(timer);el.style.opacity='0';setTimeout(function(){el.remove()},400)});});})();</script>

        <div class="storage-box">
            <div style="display:flex; justify-content:space-between; font-size:14px;">
                <span id="storageUsedText"><b>Storage Used:</b> {{ '%.2f'|format(used_gb) }} GB used / {{ quota_gb|int }} GB allocated</span>
                <span id="storagePctText">{{ storage_pct }}%</span>
            </div>
            <div class="progress-bar"><div id="storageProgressFill" class="progress-fill" style="width: {{ storage_pct }}%;"></div></div>
            <div id="storageQuotaNotice" role="status" aria-live="polite" style="display:{{ 'block' if available_bytes <= 0 else 'none' }};margin-top:12px;padding:11px 13px;border-radius:8px;border:1px solid rgba(239,68,68,.45);background:rgba(239,68,68,.10);color:#fecaca;">
                <strong id="storageQuotaNoticeTitle">{% if available_bytes <= 0 %}Storage is full.{% else %}Storage space is low.{% endif %}</strong>
                <span id="storageQuotaNoticeText">{% if available_bytes <= 0 %}Delete files you no longer need to make room for more uploads.{% else %}Check available space before uploading more files.{% endif %}</span>
                <button type="button" id="storageClearSpaceBtn" class="btn-icon" style="margin-left:8px;padding:5px 9px;">Manage files</button>
            </div>
        </div>
        <div class="toolbar">
            <div style="display:flex; align-items:center; gap:12px;">
                <input type="checkbox" id="selectAllCheckbox" class="item-checkbox" title="Select All Items">
                <span id="currentFolderTitle" style="font-weight:600; font-size:15px; color:#00f0ff;">{{ folder_title }}</span>
            </div>
            <div class="tool-buttons">
                <button type="button" class="btn-icon btn-bulk-action btn-bulk-download" id="btnBulkDownload">📥 Download Selected (<span id="selectedDownloadCount">0</span>)</button>
                <button type="button" class="btn-icon btn-bulk-action btn-bulk-delete" id="btnBulkDelete">🗑️ Delete Selected (<span id="selectedDeleteCount">0</span>)</button>
                {% if parent_url %}
                <button type="button" class="btn-icon" onclick="location.href='{{ parent_url }}'">⬆️ Back</button>
                {% endif %}
                <button type="button" class="btn-icon" id="btnOpenFolderModal">📁+ New Folder</button>
                <button type="button" class="btn-icon" id="btnOpenUploadModal">📤 Upload Files</button>
            </div>
        </div>

        <div id="fileContentsList" class="drop-target-area">
            {% if items %}
            <ul>
                {% for item in items %}
                <li>
                    <span style="display:flex; align-items:center; min-width:0; flex:1; overflow:hidden; margin-right:12px;">
                        <input type="checkbox" class="item-checkbox item-select" data-url="{{ item.file_url }}" data-rel="{{ item.rel_path }}" data-name="{{ item.name }}" data-isdir="{{ item.is_dir }}">
                        {% if item.is_dir %}📁{% elif item.media_type == 'video' %}🎬{% elif item.media_type == 'audio' %}🎵{% elif item.media_type == 'image' %}🖼️{% elif item.media_type == 'document' %}📚{% elif item.media_type == 'code' %}⌨️{% else %}📄{% endif %}
                        &nbsp;
                        {% if item.media_type %}
                        <a href="javascript:void(0)" class="btn-preview file-list-name" title="{{ item.name }}" data-url="{{ item.file_url }}" data-name="{{ item.name }}" data-type="{{ item.media_type }}" data-rel="{{ item.rel_path }}" style="color:#00f0ff; text-decoration:none;">{{ item.name[:20] }}{% if item.name|length > 20 %}...{% endif %}</a>
                        {% elif item.is_dir %}
                        <a href="{{ item.file_url }}" class="file-list-name" title="{{ item.name }}" style="color:#00f0ff; text-decoration:none;">{{ item.name[:20] }}{% if item.name|length > 20 %}...{% endif %}</a>
                        {% else %}
                        <span class="file-list-name" title="{{ item.name }}" style="color:#e2e8f0;">{{ item.name[:20] }}{% if item.name|length > 20 %}...{% endif %}</span>
                        {% endif %}
                    </span>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span style="font-size:12px; color:#94a3b8; margin-right:8px;">{{ item.size_str }}</span>
                        {% if item.media_type %}
                        <button type="button" class="btn-action btn-preview" data-url="{{ item.file_url }}" data-name="{{ item.name }}" data-type="{{ item.media_type }}" data-rel="{{ item.rel_path }}">👁️ View</button>
                        {% endif %}
                        <button type="button" class="btn-action btn-download" title="Download" aria-label="Download {{ item.name }}" data-url="{{ item.file_url }}" data-name="{% if item.is_dir %}{{ item.name }}.zip{% else %}{{ item.name }}{% endif %}" data-isdir="{{ item.is_dir }}">📥</button>
                        <button type="button" class="btn-action btn-rename btn-single-rename" title="Rename" aria-label="Rename {{ item.name }}" data-rel="{{ item.rel_path }}" data-name="{{ item.name }}">✏️</button>
                        <button type="button" class="btn-delete btn-single-delete" title="Delete" aria-label="Delete {{ item.name }}" data-rel="{{ item.rel_path }}" data-name="{{ item.name }}">🗑️</button>
                    </div>
                </li>
                {% endfor %}
            </ul>
            <div style="text-align:center; font-size:13px; color:#64748b; margin-top:20px; padding-top:12px; border-top:1px dashed #1f2937;">📥 Drag & Drop files anywhere into this window to upload</div>
            {% else %}
            <div class="empty-box">
                <span style="font-size: 54px; display: block; margin-bottom: 12px;">📂</span>
                <p style="color: #94a3b8; margin: 0 0 10px 0; font-size: 16px;">This folder is empty.</p>
                <p style="color: #00f0ff; font-size: 14px; font-weight: 600; margin: 0;">📥 Drag & drop multiple files anywhere into this box to upload</p>
            </div>
            {% endif %}
        </div>
    </div>

    <script>
        let selectedFileObjects = [];
        let itemsToDelete = [];
        let selectedTargetRelPath = '{{ current_rel_path }}';
        let pickerCurrentRelPath = '{{ current_rel_path }}';

        // UNIVERSAL SMOOTH MODAL HELPERS
        function showModal(id) {
            const el = document.getElementById(id);
            if (el) {
                el.classList.add('active');
                const input = el.querySelector('[data-autofocus]');
                if (input) {
                    // Wait until the modal is visible and its entrance transition has begun.
                    setTimeout(() => {
                        input.focus({ preventScroll: true });
                        if (typeof input.select === 'function') input.select();
                    }, 120);
                }
            }
        }

        function hideModal(id) {
            const el = document.getElementById(id);
            if (el) el.classList.remove('active');
        }

        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
            if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
            return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
        }

        function showDriveMessage(title, message) {
            let box = document.getElementById('driveMessageDialog');
            if (!box) {
                box = document.createElement('div'); box.id='driveMessageDialog'; box.className='modal-overlay';
                box.style.cssText='z-index:6200;display:none;align-items:center;justify-content:center;';
                const card=document.createElement('div'); card.className='modal-card'; card.style.width='min(500px,94vw)';
                const heading=document.createElement('h3'); heading.id='driveMessageTitle'; heading.style.color='#fbbf24';
                const body=document.createElement('p'); body.id='driveMessageBody'; body.style.cssText='color:#cbd5e1;line-height:1.6;white-space:pre-wrap;';
                const actions=document.createElement('div'); actions.style.cssText='display:flex;justify-content:flex-end;margin-top:16px;';
                const button=document.createElement('button'); button.type='button'; button.className='btn-icon'; button.textContent='Got it';
                button.onclick=()=>{box.classList.remove('active');box.style.display='none';}; actions.appendChild(button); card.append(heading,body,actions); box.appendChild(card); document.body.appendChild(box);
                box.addEventListener('click',e=>{if(e.target===box){box.classList.remove('active');box.style.display='none';}});
            }
            document.getElementById('driveMessageTitle').textContent=title;
            document.getElementById('driveMessageBody').textContent=message;
            box.style.display='flex'; box.classList.add('active');
        }

        const transferHistoryDialog=document.getElementById('transferHistoryDialog');
        const transferHistoryList=document.getElementById('transferHistoryList');
        async function loadTransferHistory(){
            if(!transferHistoryList)return; transferHistoryList.textContent='Loading transfer history…';
            try{const r=await fetch('/api/transfer-history',{headers:{'Accept':'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not load history');
                transferHistoryList.replaceChildren();
                if(!d.events.length){transferHistoryList.textContent='No transfers recorded in the last 10 days.';return;}
                d.events.forEach(ev=>{const row=document.createElement('div');row.style.cssText='padding:13px 8px;border-bottom:1px solid #263448;display:grid;grid-template-columns:minmax(140px,1.2fr) minmax(100px,.6fr) minmax(120px,1fr);gap:10px;align-items:center;';
                    const name=document.createElement('strong');name.textContent=ev.item||'Transfer';name.style.overflowWrap='anywhere';
                    const state=document.createElement('span');state.textContent=ev.action+' · '+ev.status;state.style.color=ev.status==='Success'?'#6ee7b7':(ev.status==='Cancelled'?'#fbbf24':'#fca5a5');
                    const meta=document.createElement('span');meta.textContent=ev.time+(ev.size?' · '+ev.size:'');meta.style.cssText='color:#94a3b8;font-size:12px;';row.append(name,state,meta);transferHistoryList.appendChild(row);
                });
            }catch(e){transferHistoryList.textContent=e.message||'Could not load transfer history.';}
        }
        async function recordTransfer(action,item,status,size){
            try{const token=document.querySelector('meta[name="csrf-token"]')?.content||'';await fetch('/api/transfer-history',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':token,'Accept':'application/json'},body:JSON.stringify({action,item,status,size})});}catch(_){/* Transfer itself must not fail if history logging is unavailable. */}
        }
        document.getElementById('openTransferHistory')?.addEventListener('click',()=>{transferHistoryDialog.style.display='flex';transferHistoryDialog.classList.add('active');loadTransferHistory();});
        document.getElementById('closeTransferHistory')?.addEventListener('click',()=>{transferHistoryDialog.classList.remove('active');transferHistoryDialog.style.display='none';});
        document.getElementById('clearTransferHistory')?.addEventListener('click',async()=>{
            if(!confirm('Clear your transfer history? This does not delete any files.'))return;
            try{const token=document.querySelector('meta[name="csrf-token"]')?.content||'';const r=await fetch('/api/transfer-history/clear',{method:'POST',headers:{'X-CSRF-Token':token,'Accept':'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not clear history');await loadTransferHistory();}
            catch(e){showDriveMessage('Could not clear log',e.message||'Please try again.');}
        });

        function sanitizePathDisplay(rawPath, rootName) {
            if (!rawPath) return rootName;
            let clean = rawPath.replace(/\\/g, '/').replace(/^[\/\\]+|[\/\\]+$/g, '');
            return clean ? clean : rootName;
        }

        // SMOOTH TRANSFER MANAGER ENGINE
        function addTransferCard(name, actionLabel) {
            const queue = document.getElementById('transferQueue');
            queue.classList.add('active');
            const id = 'transfer_' + Math.random().toString(36).substr(2, 9);
            const card = document.createElement('div');
            card.className = 'transfer-item';
            card.id = id;
            const info = document.createElement('div');
            info.className = 'transfer-info';
            const label = document.createElement('span');
            label.style.cssText = 'color:#e2e8f0; font-weight:500;';
            label.textContent = actionLabel + ': ' + name;
            const percent = document.createElement('span');
            percent.className = 'percent';
            percent.style.cssText = 'color:#00f0ff; font-weight:bold;';
            percent.textContent = '0%';
            info.append(label, percent);
            const bg = document.createElement('div');
            bg.className = 'transfer-bar-bg';
            const fill = document.createElement('div');
            fill.className = 'transfer-bar-fill';
            fill.style.width = '0%';
            bg.appendChild(fill);
            card.append(info, bg);
            document.getElementById('queueList').appendChild(card);
            return id;
        }

        function updateTransferCard(id, pct) {
            const card = document.getElementById(id);
            if (card) {
                card.querySelector('.percent').textContent = pct + '%';
                card.querySelector('.transfer-bar-fill').style.width = pct + '%';
            }
        }

        function removeTransferCardSmooth(id) {
            const card = document.getElementById(id);
            if (card) {
                card.classList.add('fading-out');
                setTimeout(() => {
                    card.remove();
                    const list = document.getElementById('queueList');
                    if (!list || list.children.length === 0) {
                        document.getElementById('transferQueue').classList.remove('active');
                    }
                }, 650);
            }
        }

        // DIRECT DOWNLOAD ENGINE
        function downloadDirectly(url, filename, isDir = false) {
            if (isDir && !filename.toLowerCase().endsWith('.zip')) {
                filename += '.zip';
            }

            const transferId = addTransferCard(filename, 'Downloading');
            updateTransferCard(transferId, 100);

            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();

            setTimeout(() => removeTransferCardSmooth(transferId), 2200);
        }

        function openDirPickerModal(initialRelPath) {
            pickerCurrentRelPath = initialRelPath || '';
            loadDirPickerContents(pickerCurrentRelPath);
            showModal('dirPickerModal');
        }

        function closeDirPickerModal() {
            hideModal('dirPickerModal');
        }

        async function loadDirPickerContents(relPath) {
            const listEl = document.getElementById('dirPickerList');
            const pathTextEl = document.getElementById('dirPickerPathText');
            listEl.innerHTML = '<div style="color:#94a3b8; text-align:center; padding:20px;">Loading folders...</div>';

            try {
                const res = await fetch('/api/list-folders/' + relPath);
                if (!res.ok) throw new Error('Failed to fetch folders');
                const data = await res.json();
                
                pickerCurrentRelPath = data.current_rel;
                pathTextEl.textContent = 'Location: ' + sanitizePathDisplay(data.display_path, data.user_root_name);

                listEl.replaceChildren();
                if (data.parent_rel !== null) {
                    const up = document.createElement('div');
                    up.className = 'dir-picker-item';
                    up.style.color = '#38bdf8';
                    up.textContent = '⬆️ .. (Go Up)';
                    up.addEventListener('click', () => loadDirPickerContents(data.parent_rel));
                    listEl.appendChild(up);
                }
                if (data.folders.length === 0) {
                    const empty = document.createElement('div');
                    empty.style.cssText = 'color:#64748b; padding:12px; text-align:center;';
                    empty.textContent = 'No subfolders in this directory';
                    listEl.appendChild(empty);
                } else {
                    for (const f of data.folders) {
                        const item = document.createElement('div');
                        item.className = 'dir-picker-item';
                        const label = document.createElement('span');
                        const name = document.createElement('b');
                        name.textContent = f.name;
                        label.append('📁 ', name);
                        const open = document.createElement('span');
                        open.style.cssText = 'font-size:12px; color:#38bdf8;';
                        open.textContent = 'Open ➔';
                        item.append(label, open);
                        item.addEventListener('click', () => loadDirPickerContents(f.rel_path));
                        listEl.appendChild(item);
                    }
                }
            } catch (err) {
                listEl.innerHTML = '<div style="color:#f87171; text-align:center; padding:20px;">Error loading folders.</div>';
            }
        }

        function confirmSelectedDir() {
            selectedTargetRelPath = pickerCurrentRelPath;
            document.getElementById('targetDirDisplay').textContent = sanitizePathDisplay(selectedTargetRelPath, '{{ user_folder_name }}');
            closeDirPickerModal();
        }

        function updateSelectionUI() {
            const checkboxes = document.querySelectorAll('.item-select');
            const selected = Array.from(checkboxes).filter(c => c.checked);
            
            const bulkDownloadBtn = document.getElementById('btnBulkDownload');
            const bulkDeleteBtn = document.getElementById('btnBulkDelete');
            
            const countDl = document.getElementById('selectedDownloadCount');
            const countDel = document.getElementById('selectedDeleteCount');

            if (selected.length > 0) {
                bulkDownloadBtn.style.display = 'inline-flex';
                bulkDeleteBtn.style.display = 'inline-flex';
                countDl.textContent = selected.length;
                countDel.textContent = selected.length;
            } else {
                bulkDownloadBtn.style.display = 'none';
                bulkDeleteBtn.style.display = 'none';
            }

            const selectAll = document.getElementById('selectAllCheckbox');
            if (selectAll && checkboxes.length > 0) {
                selectAll.checked = (selected.length === checkboxes.length);
            }
        }

        document.addEventListener('change', function(e) {
            if (e.target.classList.contains('item-select')) {
                updateSelectionUI();
            } else if (e.target.id === 'selectAllCheckbox') {
                const checkboxes = document.querySelectorAll('.item-select');
                checkboxes.forEach(c => c.checked = e.target.checked);
                updateSelectionUI();
            }
        });

        // MULTI-SELECT BULK ZIP DOWNLOAD ENGINE
        document.getElementById('btnBulkDownload').onclick = function() {
            const selected = Array.from(document.querySelectorAll('.item-select:checked'));
            if (!selected.length) return;

            const count = selected.length;
            const transferId = addTransferCard(count + ' item(s) (.zip)', 'Zipping & Downloading');
            updateTransferCard(transferId, 50);

            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/api/bulk-download';
            const csrf = document.createElement('input');
            csrf.type = 'hidden'; csrf.name = '_csrf_token';
            csrf.value = document.querySelector('meta[name="csrf-token"]').content;
            form.appendChild(csrf);
            form.style.display = 'none';

            selected.forEach(el => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'item_path';
                input.value = el.dataset.rel;
                form.appendChild(input);
            });

            document.body.appendChild(form);
            form.submit();
            form.remove();

            setTimeout(() => {
                updateTransferCard(transferId, 100);
                setTimeout(() => removeTransferCardSmooth(transferId), 2000);
            }, 600);
        };

        // BULK DELETE CONFIRMATION
        document.getElementById('btnBulkDelete').onclick = function() {
            const selected = Array.from(document.querySelectorAll('.item-select:checked'));
            itemsToDelete = selected.map(s => s.dataset.rel);
            document.getElementById('deleteItemText').textContent = 'Are you sure you want to delete ' + itemsToDelete.length + ' selected item(s)?';
            showModal('deleteModal');
        };

        document.addEventListener('click', function(e) {
            const previewBtn = e.target.closest('.btn-preview');
            if (previewBtn) {
                e.preventDefault();
                openMediaModal(previewBtn.dataset.url, previewBtn.dataset.name, previewBtn.dataset.type, previewBtn.dataset.rel);
                return;
            }

            const downloadBtn = e.target.closest('.btn-download');
            if (downloadBtn) {
                e.preventDefault();
                const isDir = downloadBtn.dataset.isdir === 'True' || downloadBtn.dataset.isdir === 'true';
                downloadDirectly(downloadBtn.dataset.url + '?download=1', downloadBtn.dataset.name, isDir);
                return;
            }

            const renameBtn = e.target.closest('.btn-single-rename');
            if (renameBtn) {
                e.preventDefault();
                document.getElementById('renameItemText').textContent = 'Rename: ' + renameBtn.dataset.name;
                document.getElementById('renameItemNameInput').value = renameBtn.dataset.name;
                document.getElementById('renameItemNameInput').dataset.rel = renameBtn.dataset.rel;
                showModal('renameModal');
                return;
            }

            const singleDeleteBtn = e.target.closest('.btn-single-delete');
            if (singleDeleteBtn) {
                e.preventDefault();
                itemsToDelete = [singleDeleteBtn.dataset.rel];
                document.getElementById('deleteItemText').textContent = 'Are you sure you want to delete "' + singleDeleteBtn.dataset.name + '"?';
                showModal('deleteModal');
                return;
            }
        });

        document.getElementById('btnOpenFolderModal').onclick = () => {
            document.getElementById('newFolderNameInput').value = '';
            showModal('folderModal');
        };
        document.getElementById('btnCancelFolder').onclick = () => hideModal('folderModal');
        async function createFolder() {
            const input = document.getElementById('newFolderNameInput');
            const name = input.value.trim();
            if (!name) { input.focus(); return; }
            const fd = new FormData();
            fd.append('action', 'create_folder');
            fd.append('folder_name', name);
            try {
                const res = await fetch(window.location.pathname, { method: 'POST', body: fd, headers: {'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content} });
                const data = await res.json();
                if (!res.ok || data.status !== 'success') { alert(data.message || 'Could not create folder.'); return; }
                hideModal('folderModal');
                window.location.reload();
            } catch (err) { alert('Could not create folder. Please try again.'); }
        }
        document.getElementById('btnExecuteFolder').onclick = createFolder;
        document.getElementById('newFolderNameInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') { e.preventDefault(); createFolder(); }
            if (e.key === 'Escape') hideModal('folderModal');
        });

        document.getElementById('btnCancelRename').onclick = () => hideModal('renameModal');
        async function renameItem() {
            const input = document.getElementById('renameItemNameInput');
            const name = input.value.trim();
            const oldPath = input.dataset.rel;
            if (!name || !oldPath) { input.focus(); return; }
            const fd = new FormData();
            fd.append('action', 'rename');
            fd.append('item_path', oldPath);
            fd.append('new_name', name);
            try {
                const res = await fetch(window.location.pathname, { method: 'POST', body: fd, headers: {'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content} });
                const data = await res.json();
                if (!res.ok || data.status !== 'success') { alert(data.message || 'Could not rename item.'); return; }
                hideModal('renameModal');
                window.location.reload();
            } catch (err) { alert('Could not rename item. Please try again.'); }
        }
        document.getElementById('btnExecuteRename').onclick = renameItem;
        document.getElementById('renameItemNameInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') { e.preventDefault(); renameItem(); }
            if (e.key === 'Escape') hideModal('renameModal');
        });

        const activeUploadRequests = new Set();
        let liveAvailableBytes = {{ available_bytes|int }};
        let uploadLeaveTarget = null;
        let allowUploadNavigation = false;
        function setStorageBarState(pct) {
            const fill = document.getElementById('storageProgressFill');
            if (!fill) return;
            const value = Math.max(0, Math.min(100, Number(pct) || 0));
            fill.style.width = value + '%';
            let color = '#10b981', glow = 'rgba(16,185,129,.8)';
            if (value >= 85) { color = '#ef4444'; glow = 'rgba(239,68,68,.8)'; }
            else if (value >= 60) { color = '#f59e0b'; glow = 'rgba(245,158,11,.8)'; }
            fill.style.backgroundColor = color;
            fill.style.boxShadow = '0 0 12px ' + glow;
            fill.style.backgroundImage = 'linear-gradient(90deg, rgba(255,255,255,.1) 0%, rgba(255,255,255,.85) 50%, rgba(255,255,255,.1) 100%)';
            const pctText = document.getElementById('storagePctText');
            if (pctText) { pctText.textContent = Math.round(value) + '%'; pctText.style.color = color; }
        }
        function updateQuotaNotice(pct, availableBytes, selectedBytes) {
            const notice = document.getElementById('storageQuotaNotice');
            const title = document.getElementById('storageQuotaNoticeTitle');
            const message = document.getElementById('storageQuotaNoticeText');
            if (!notice || !title || !message) return;
            const noSpace = Number(availableBytes) <= 0;
            // This notice represents the account's actual storage state only. A rejected
            // file selection is temporary and must never leave a sticky banner behind.
            if (noSpace || Number(pct) >= 95) {
                notice.style.display = 'block';
                title.textContent = noSpace ? 'Storage is full.' : 'Storage is almost full.';
                message.textContent = noSpace ? 'Delete files you no longer need to make room for more uploads.' : 'You have very little space left. Delete files to make room for more uploads.';
            } else { notice.style.display = 'none'; }
        }
        const storageClearSpaceBtn = document.getElementById('storageClearSpaceBtn');
        if (storageClearSpaceBtn) storageClearSpaceBtn.addEventListener('click', function(){
            const area = document.getElementById('fileContentsList');
            if (area) { area.scrollIntoView({behavior:'smooth',block:'start'}); area.style.outline='2px solid rgba(239,68,68,.7)'; setTimeout(()=>{area.style.outline='';},1800); }
            const firstSelectable = document.querySelector('.item-select');
            if (firstSelectable) firstSelectable.focus({preventScroll:true});
        });
        function showUploadLeavePrompt(target) {
            uploadLeaveTarget = target;
            const dialog = document.getElementById('uploadLeaveDialog');
            if (dialog) { dialog.style.display='flex'; dialog.classList.add('active'); dialog.setAttribute('aria-hidden','false'); document.body.style.overflow='hidden'; const stay=document.getElementById('stayUploadingBtn'); if(stay) stay.focus(); }
        }
        function hideUploadLeavePrompt(){ const dialog=document.getElementById('uploadLeaveDialog'); if(dialog){dialog.classList.remove('active');dialog.style.display='none';dialog.setAttribute('aria-hidden','true');} document.body.style.overflow=''; uploadLeaveTarget=null; }
        document.addEventListener('keydown', function(e){
            const dialog=document.getElementById('uploadLeaveDialog');
            if (!dialog || dialog.style.display === 'none' || dialog.style.display === '') return;
            if (e.key === 'Escape') { e.preventDefault(); hideUploadLeavePrompt(); }
        });
        document.getElementById('stayUploadingBtn').addEventListener('click', hideUploadLeavePrompt);
        document.getElementById('forceLeaveUploadingBtn').addEventListener('click', function(){
            activeUploadRequests.forEach(xhr=>{try{xhr.abort();}catch(_){}}); activeUploadRequests.clear();
            const queue=document.getElementById('queueList');
            if(queue) queue.querySelectorAll('.transfer-item').forEach(card=>{const label=card.querySelector('.transfer-info span'); if(label) label.textContent='Upload cancelled'; const pct=card.querySelector('.percent'); if(pct) pct.textContent='Cancelled';});
            allowUploadNavigation=true; const target=uploadLeaveTarget; hideUploadLeavePrompt();
            if(target) window.location.href=target;
        });
        // Use Cyber Drive's own dialog for in-app navigation, and Chrome's native
        // confirmation for tab close, refresh, or other browser-level navigation.
        // Chrome controls the wording and may require prior user interaction.
        window.addEventListener('beforeunload', function(e){
            if (!activeUploadRequests.size || allowUploadNavigation) return;
            e.preventDefault();
            e.returnValue = '';
            return '';
        });
        document.addEventListener('click', function(e){
            if (!activeUploadRequests.size || allowUploadNavigation || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            const link = e.target.closest('a[href]');
            if (!link || link.target === '_blank' || link.hasAttribute('download')) return;
            const rawHref = link.getAttribute('href') || '';
            if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:') || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) return;
            let targetUrl;
            try { targetUrl = new URL(link.href, window.location.href); } catch (_) { return; }
            if (targetUrl.origin !== window.location.origin) return;
            e.preventDefault();
            showUploadLeavePrompt(targetUrl.href);
        }, true);
        // A custom HTML dialog cannot replace Chrome's tab-close confirmation. If the
        // user confirms leaving, abort unfinished transfers when the page actually leaves.
        window.addEventListener('pagehide',function(){if(activeUploadRequests.size){activeUploadRequests.forEach(xhr=>{try{xhr.abort();}catch(_){}});activeUploadRequests.clear();}});

        function processFileSelection(files) {
            if (!files || !files.length) return;
            selectedFileObjects = Array.from(files);
            let totalBytes = selectedFileObjects.reduce((acc, f) => acc + f.size, 0);
            const availableBytesNow = liveAvailableBytes;
            const currentPctAtPageLoad = parseInt((document.getElementById('storagePctText') || {}).textContent || '{{ storage_pct|int }}', 10) || 0;
            if (totalBytes > availableBytesNow) {
                // Clear any previous selection-related state immediately. The quota banner
                // is reserved for genuinely full/almost-full storage, not rejected picks.
                updateQuotaNotice(currentPctAtPageLoad, availableBytesNow, 0);
                const availableGb = (availableBytesNow / (1024*1024*1024)).toFixed(2);
                showDriveMessage('Not enough storage', 'Available space: ' + availableGb + ' GB. Delete files you no longer need or choose a smaller upload.');
                document.getElementById('hiddenFileInput').value = '';
                selectedFileObjects = [];
                return;
            }
            updateQuotaNotice(currentPctAtPageLoad, availableBytesNow, 0);

            const count = selectedFileObjects.length;
            const sizeFormatted = formatBytes(totalBytes);
            if (count === 1) {
                document.getElementById('uploadFileInfo').textContent = 'File: ' + selectedFileObjects[0].name + ' (' + sizeFormatted + ')';
            } else {
                document.getElementById('uploadFileInfo').textContent = 'Selected ' + count + ' files (' + sizeFormatted + ' total)';
            }
            
            document.getElementById('targetDirDisplay').textContent = sanitizePathDisplay(selectedTargetRelPath, '{{ user_folder_name }}');
            showModal('uploadModal');
        }

        document.getElementById('btnOpenUploadModal').onclick = () => document.getElementById('hiddenFileInput').click();
        document.getElementById('hiddenFileInput').onchange = function() {
            processFileSelection(this.files);
        };
        document.getElementById('btnCancelUpload').onclick = function() {
            hideModal('uploadModal');
            document.getElementById('hiddenFileInput').value = '';
            selectedFileObjects = [];
        };

        document.getElementById('btnExecuteUpload').onclick = async function() {
            if (!selectedFileObjects || !selectedFileObjects.length) return;
            const filesToUpload = Array.from(selectedFileObjects);
            const targetPath = selectedTargetRelPath;
            const totalBytes = filesToUpload.reduce((n, f) => n + f.size, 0);
            const names = filesToUpload.map(f => f.name).join(', ');
            const sizeText = formatBytes(totalBytes);
            const csrf = document.querySelector('meta[name="csrf-token"]').content;
            let reservationToken = '';
            const executeButton = document.getElementById('btnExecuteUpload');
            executeButton.disabled = true;
            const originalExecuteText = executeButton.textContent;
            executeButton.textContent = 'Checking storage…';
            try {
                const reserveResponse = await fetch('/api/upload-reservation', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'Accept':'application/json'}, body:JSON.stringify({bytes:totalBytes})});
                const reserveData = await reserveResponse.json();
                if (!reserveResponse.ok || !reserveData.ok) {
                    showDriveMessage('Upload rejected before starting', (reserveData.error || 'There is not enough storage for this upload and other pending uploads.') + ' No file data was uploaded.');
                    return;
                }
                reservationToken = reserveData.token;
            } catch (_) {
                showDriveMessage('Storage check failed', 'Cyber Drive could not reserve space. The upload has not started; please retry.');
                return;
            } finally { executeButton.disabled = false; executeButton.textContent = originalExecuteText; }

            const uploadUrl = '/files/' + targetPath;
            const fd = new FormData();
            fd.append('action', 'upload');
            fd.append('reservation_token', reservationToken);
            for (const f of filesToUpload) fd.append('file', f);

            hideModal('uploadModal');
            const transferId = addTransferCard(filesToUpload.length + ' file(s)', 'Uploading');
            const xhr = new XMLHttpRequest();
            activeUploadRequests.add(xhr);
            let releaseSent = false;
            const releaseReservation = () => {
                if (releaseSent || !reservationToken) return;
                releaseSent = true;
                fetch('/api/upload-reservation/release', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'Accept':'application/json'}, body:JSON.stringify({token:reservationToken})}).catch(()=>{});
            };
            xhr.upload.onprogress = function(e) {
                if (e.lengthComputable) updateTransferCard(transferId, Math.round((e.loaded / e.total) * 100));
            };
            xhr.onload = function() {
                activeUploadRequests.delete(xhr);
                releaseReservation();
                let result = {};
                try { result = JSON.parse(xhr.responseText || '{}'); } catch (_) {}
                if (xhr.status >= 200 && xhr.status < 300 && result.status === 'success') {
                    updateTransferCard(transferId, 100);
                    const title = document.getElementById('storageQuotaNoticeTitle');
                    if (title) title.textContent = 'Upload complete.';
                    setTimeout(() => { removeTransferCardSmooth(transferId); syncFilesFromServer(); }, 600);
                } else {
                    recordTransfer('Upload', names, 'Failed', sizeText);
                    const card = document.getElementById(transferId);
                    if (card) { const label=card.querySelector('.transfer-info span'); if(label) label.textContent='Upload failed'; const pct=card.querySelector('.percent'); if(pct) pct.textContent='Failed'; }
                    showDriveMessage(xhr.status===413?'Storage limit exceeded':'Upload failed', result.message || 'Check your available storage and try again.');
                    setTimeout(() => removeTransferCardSmooth(transferId), 2200);
                    syncFilesFromServer();
                }
            };
            xhr.onerror = function(){ activeUploadRequests.delete(xhr); releaseReservation(); recordTransfer('Upload', names, 'Failed', sizeText); showDriveMessage('Network error','The upload was interrupted. Please try again.'); removeTransferCardSmooth(transferId); };
            xhr.onabort = function(){ activeUploadRequests.delete(xhr); releaseReservation(); recordTransfer('Upload', names, 'Cancelled', sizeText); const card=document.getElementById(transferId); if(card){const label=card.querySelector('.transfer-info span');if(label)label.textContent='Upload cancelled';const pct=card.querySelector('.percent');if(pct)pct.textContent='Cancelled';} };
            xhr.open('POST', uploadUrl, true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.setRequestHeader('X-CSRF-Token', document.querySelector('meta[name="csrf-token"]').content);
            xhr.send(fd);
        };

        let dragCounter = 0;
        const dragOverlay = document.getElementById('dragDropOverlay');
        const dropArea = document.getElementById('fileContentsList');

        window.addEventListener('dragenter', function(e) {
            e.preventDefault();
            dragCounter++;
            if (dragOverlay) dragOverlay.classList.add('active');
            if (dropArea) dropArea.classList.add('drag-over');
        });

        window.addEventListener('dragleave', function(e) {
            e.preventDefault();
            dragCounter--;
            if (dragCounter <= 0) {
                dragCounter = 0;
                if (dragOverlay) dragOverlay.classList.remove('active');
                if (dropArea) dropArea.classList.remove('drag-over');
            }
        });

        window.addEventListener('dragover', function(e) { e.preventDefault(); });

        window.addEventListener('drop', function(e) {
            e.preventDefault();
            dragCounter = 0;
            if (dragOverlay) dragOverlay.classList.remove('active');
            if (dropArea) dropArea.classList.remove('drag-over');

            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                processFileSelection(e.dataTransfer.files);
            }
        });

        // LIVE FILESYSTEM SYNC: periodically refresh this view from the server so
        // uploads, deletes, renames, and OS-level changes appear on other devices.
        function makeLiveItem(item) {
            const li = document.createElement('li');
            const left = document.createElement('span');
            left.style.cssText = 'display:flex;align-items:center;min-width:0;flex:1;overflow:hidden;margin-right:12px;';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox'; checkbox.className = 'item-checkbox item-select';
            checkbox.dataset.url = item.file_url; checkbox.dataset.rel = item.rel_path;
            checkbox.dataset.name = item.name; checkbox.dataset.isdir = String(item.is_dir);
            checkbox.checked = liveSelectedPaths.has(item.rel_path);
            left.appendChild(checkbox);
            const icon = item.is_dir ? '📁' : item.media_type === 'video' ? '🎬' : item.media_type === 'audio' ? '🎵' : item.media_type === 'image' ? '🖼️' : item.media_type === 'document' ? '📚' : item.media_type === 'code' ? '⌨️' : '📄';
            left.append(document.createTextNode(icon + ' '));
            if (item.media_type) {
                const a = document.createElement('a'); a.href = 'javascript:void(0)'; a.className = 'btn-preview';
                a.dataset.url = item.file_url; a.dataset.name = item.name; a.dataset.type = item.media_type; a.dataset.rel = item.rel_path;
                a.style.cssText = 'color:#00f0ff;text-decoration:none;'; a.title = item.name; a.textContent = item.name.length > 20 ? item.name.slice(0, 20) + '...' : item.name; left.appendChild(a);
            } else if (item.is_dir) {
                const a = document.createElement('a'); a.href = item.file_url; a.style.cssText = 'color:#00f0ff;text-decoration:none;'; a.title = item.name; a.textContent = item.name.length > 20 ? item.name.slice(0, 20) + '...' : item.name; left.appendChild(a);
            } else {
                const label = document.createElement('span'); label.style.color = '#e2e8f0'; label.title = item.name; label.textContent = item.name.length > 20 ? item.name.slice(0, 20) + '...' : item.name; left.appendChild(label);
            }
            const actions = document.createElement('div'); actions.style.cssText = 'display:flex;gap:8px;align-items:center;';
            const size = document.createElement('span'); size.style.cssText = 'font-size:12px;color:#94a3b8;margin-right:8px;'; size.textContent = item.size_str; actions.appendChild(size);
            if (item.media_type) {
                const view = document.createElement('button'); view.type='button'; view.className='btn-action btn-preview'; view.dataset.url=item.file_url; view.dataset.name=item.name; view.dataset.type=item.media_type; view.dataset.rel=item.rel_path; view.textContent='👁️ View'; actions.appendChild(view);
            }
            const dl = document.createElement('button'); dl.type='button'; dl.className='btn-action btn-download'; dl.title='Download'; dl.setAttribute('aria-label','Download '+item.name); dl.dataset.url=item.file_url; dl.dataset.name=item.is_dir ? item.name+'.zip' : item.name; dl.dataset.isdir=String(item.is_dir); dl.textContent='📥'; actions.appendChild(dl);
            const rename = document.createElement('button'); rename.type='button'; rename.className='btn-action btn-rename btn-single-rename'; rename.title='Rename'; rename.setAttribute('aria-label','Rename '+item.name); rename.dataset.rel=item.rel_path; rename.dataset.name=item.name; rename.textContent='✏️'; actions.appendChild(rename);
            const del = document.createElement('button'); del.type='button'; del.className='btn-delete btn-single-delete'; del.title='Delete'; del.setAttribute('aria-label','Delete '+item.name); del.dataset.rel=item.rel_path; del.dataset.name=item.name; del.textContent='🗑️'; actions.appendChild(del);
            li.append(left, actions); return li;
        }

        let liveSelectedPaths = new Set();
        let liveSyncBusy = false;
        let lastLiveSignature = null;
        let lastObservedAccountState = null;
        async function syncFilesFromServer() {
            if (liveSyncBusy || document.visibilityState !== 'visible') return;
            // Avoid replacing the file list while a dialog or media viewer is open.
            if (document.querySelector('.modal-overlay.active')) return;
            liveSyncBusy = true;
            try {
                const url = '/api/sync-files?path=' + encodeURIComponent('{{ current_rel_path }}') + '&_=' + Date.now();
                const response = await fetch(url, {cache:'no-store', credentials:'same-origin', headers:{'Accept':'application/json'}});
                if (response.status === 401 || response.redirected) return;
                if (!response.ok) return;
                const data = await response.json();
                // Account quota and request state are checked on every poll, even if
                // the current folder listing has not changed.
                const accountState = {
                    quota_gb: Number(data.quota_gb || 1),
                    quota_approved_at: data.quota_approved_at || '',
                    storage_request_pending: Boolean(data.storage_request_pending)
                };
                if (lastObservedAccountState) {
                    if (accountState.quota_gb !== lastObservedAccountState.quota_gb ||
                        accountState.quota_approved_at !== lastObservedAccountState.quota_approved_at) {
                        showDriveMessage(accountState.quota_gb > lastObservedAccountState.quota_gb ? 'Admin increased your storage 🎉' : 'Storage allocation updated',
                            'Your allocation changed from ' + lastObservedAccountState.quota_gb + ' GB to ' + accountState.quota_gb + ' GB. The new limit is active now.');
                    } else if (lastObservedAccountState.storage_request_pending && !accountState.storage_request_pending) {
                        showDriveMessage('Storage request reviewed',
                            'The admin has reviewed your request. Your current allocation is ' + accountState.quota_gb + ' GB.');
                    }
                }
                lastObservedAccountState = accountState;
                if (typeof window.updateStorageRequestQuota === 'function') window.updateStorageRequestQuota(accountState.quota_gb);
                const quotaLabel = document.getElementById('storageUsedText');
                if (quotaLabel) quotaLabel.innerHTML = '<b>Storage Used:</b> ' + Number(data.used_gb).toFixed(2) + ' GB used / ' + accountState.quota_gb + ' GB allocated';
                const signature = JSON.stringify([data.items, data.used_gb, data.storage_pct, accountState.quota_gb]);
                if (signature === lastLiveSignature) {
                    const quotaBytesNow = accountState.quota_gb * 1024 * 1024 * 1024;
                    liveAvailableBytes = Math.max(0, quotaBytesNow - (Number(data.used_gb) * 1024 * 1024 * 1024));
                    setStorageBarState(data.storage_pct);
                    updateQuotaNotice(data.storage_pct, liveAvailableBytes, 0);
                    return;
                }
                lastLiveSignature = signature;
                liveSelectedPaths = new Set(Array.from(document.querySelectorAll('.item-select:checked')).map(el => el.dataset.rel));
                const area = document.getElementById('fileContentsList');
                const list = document.createElement('ul');
                data.items.forEach(item => list.appendChild(makeLiveItem(item)));
                if (data.items.length) {
                    const hint = document.createElement('div'); hint.style.cssText='text-align:center;font-size:13px;color:#64748b;margin-top:20px;padding-top:12px;border-top:1px dashed #1f2937;';
                    hint.textContent='📥 Drag & Drop files anywhere into this window to upload';
                    area.replaceChildren(list, hint);
                } else {
                    const empty = document.createElement('div'); empty.className='empty-box';
                    const icon = document.createElement('span'); icon.style.cssText='font-size:54px;display:block;margin-bottom:12px;'; icon.textContent='📂';
                    const p = document.createElement('p'); p.style.cssText='color:#94a3b8;margin:0 0 10px 0;font-size:16px;'; p.textContent='This folder is empty.';
                    const hint = document.createElement('p'); hint.style.cssText='color:#00f0ff;font-size:14px;font-weight:600;margin:0;'; hint.textContent='📥 Drag & drop multiple files anywhere into this box to upload';
                    empty.append(icon,p,hint); area.replaceChildren(empty);
                }
                document.getElementById('storageUsedText').innerHTML = '<b>Storage Used:</b> ' + data.used_gb.toFixed(2) + ' GB used / ' + accountState.quota_gb + ' GB allocated';
                setStorageBarState(data.storage_pct);
                const quotaBytes = accountState.quota_gb * 1024 * 1024 * 1024;
                const estimatedAvailable = Math.max(0, quotaBytes - (Number(data.used_gb) * 1024 * 1024 * 1024));
                liveAvailableBytes = estimatedAvailable;
                updateQuotaNotice(data.storage_pct, estimatedAvailable, 0);
                updateSelectionUI();
            } catch (err) {
                // Keep the last successful view if a transient network error occurs.
            } finally { liveSyncBusy = false; }
        }
        setInterval(syncFilesFromServer, 1000);
        window.addEventListener('focus', syncFilesFromServer);

        // SMOOTH DELETION EXECUTION WITH TRANSFER LOGGING
        document.getElementById('btnCancelDelete').onclick = () => hideModal('deleteModal');
        document.getElementById('btnExecuteDelete').onclick = function() {
            if (!itemsToDelete.length) return;

            const count = itemsToDelete.length;
            const logName = count === 1 ? (itemsToDelete[0].split('/').pop() || itemsToDelete[0]) : (count + ' item(s)');
            
            const transferId = addTransferCard(logName, 'Deleting');
            updateTransferCard(transferId, 50);

            const fd = new FormData();
            fd.append('action', 'delete');
            for (let path of itemsToDelete) {
                fd.append('item_path', path);
            }

            hideModal('deleteModal');

            fetch(window.location.pathname, { method: 'POST', body: fd, headers: {'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content} })
                .then(res => res.json())
                .then(() => {
                    recordTransfer('Delete', logName, 'Success', '');
                    updateTransferCard(transferId, 100);
                    setTimeout(() => {
                        removeTransferCardSmooth(transferId);
                        window.location.reload();
                    }, 500);
                })
                .catch(() => {
                    recordTransfer('Delete', logName, 'Failed', '');
                    showDriveMessage('Delete failed', 'Cyber Drive could not complete the delete request. Please refresh and try again.');
                    removeTransferCardSmooth(transferId);
                    window.location.reload();
                });
        };

        let mediaKeyboardHandler = null;
        function openMediaModal(url, name, type, relPath) {
            if (mediaKeyboardHandler) { document.removeEventListener('keydown', mediaKeyboardHandler); mediaKeyboardHandler = null; }
            const title = document.getElementById('mediaTitleText');
            // Keep every media-reader title compact without changing the real filename.
            const displayName = name.length > 20 ? name.slice(0, 20) + '...' : name;
            const container = document.getElementById('mediaContainer');
            const closeButton = document.getElementById('btnCloseMediaBottom');
            const closeLabel = {
                image: 'Close Photo Viewer',
                video: 'Close Video Player',
                audio: 'Close Music Player',
                document: 'Close Document Reader',
                code: 'Close Code Viewer'
            }[type] || 'Close Media Viewer';
            closeButton.textContent = closeLabel;
            closeButton.setAttribute('aria-label', closeLabel);
            document.getElementById('btnCloseMediaTop').setAttribute('aria-label', closeLabel);
            container.innerHTML = '';
            let mediaEl = null;
            let togglePlaybackForShortcut = null;
            const makeButton = (label, cls = '') => {
                const b = document.createElement('button');
                b.type = 'button'; b.className = 'media-control-btn ' + cls; b.textContent = label;
                return b;
            };
            const makeSelect = (label, options, id) => {
                const wrap = document.createElement('label'); wrap.className = 'media-setting';
                const span = document.createElement('span'); span.textContent = label;
                const select = document.createElement('select'); select.className = 'media-select'; select.id = id;
                options.forEach(item => { const opt = document.createElement('option'); opt.value = item.value; opt.textContent = item.label; select.appendChild(opt); });
                wrap.append(span, select); return { wrap, select };
            };
            const fmtTime = seconds => {
                if (!Number.isFinite(seconds)) return '00:00';
                const n = Math.max(0, Math.floor(seconds));
                return String(Math.floor(n / 60)).padStart(2, '0') + ':' + String(n % 60).padStart(2, '0');
            };
            const showKeyHint = message => {
                let hint = document.getElementById('mediaShortcutHint');
                if (!hint) { hint = document.createElement('div'); hint.id = 'mediaShortcutHint'; hint.className = 'document-info'; hint.style.cssText = 'color:#67e8f9;min-height:18px;'; container.appendChild(hint); }
                hint.textContent = message;
                clearTimeout(hint._clearTimer);
                hint._clearTimer = setTimeout(() => { if (hint.isConnected) hint.textContent = 'Shortcut: Space Play/Pause'; }, 2600);
            };

            const outerFullscreenButton = document.getElementById('btnMediaFullscreen');
            if (outerFullscreenButton) { outerFullscreenButton.hidden = (type !== 'video'); outerFullscreenButton.disabled = (type !== 'video'); } // Fullscreen is video-only; music stays in the modal.

            if (type === 'video') {
                title.textContent = '🎬 Video Player — ' + displayName;
                const stage = document.createElement('div'); stage.className = 'media-stage';
                mediaEl = document.createElement('video');
                mediaEl.src = url; mediaEl.controls = false; mediaEl.autoplay = false;
                mediaEl.preload = 'metadata'; mediaEl.className = 'media-player-video'; mediaEl.playsInline = true;
                mediaEl.setAttribute('aria-label', 'Video player: ' + name);
                stage.appendChild(mediaEl);
                const centerPlay = makeButton('▶', 'video-center-play'); centerPlay.setAttribute('aria-label', 'Play video'); centerPlay.title = 'Play video';
                stage.appendChild(centerPlay); container.appendChild(stage);

                const panel = document.createElement('div'); panel.className = 'media-control-panel';
                const seek = document.createElement('input'); seek.type = 'range'; seek.min = '0'; seek.max = '1000'; seek.value = '0'; seek.className = 'media-seek'; seek.setAttribute('aria-label', 'Seek video');
                const timeRow = document.createElement('div'); timeRow.className = 'media-time-row';
                const currentTime = document.createElement('span'); currentTime.textContent = '00:00';
                const duration = document.createElement('span'); duration.textContent = '00:00'; timeRow.append(currentTime, duration);
                const mainRow = document.createElement('div'); mainRow.className = 'media-control-row';
                const play = makeButton('▶ Play', 'primary'); const mute = makeButton('🔊'); const volume = document.createElement('input'); volume.type = 'range'; volume.min = '0'; volume.max = '1'; volume.step = '0.05'; volume.value = '1'; volume.style.width = '90px'; volume.setAttribute('aria-label', 'Volume');
                const fullscreen = makeButton('⛶ Fullscreen');
                mainRow.append(play, mute, volume, fullscreen);
                const settingsRow = document.createElement('div'); settingsRow.className = 'media-control-row';
                const speed = makeSelect('Speed', [
                    {value:'0.5',label:'0.5×'},{value:'0.75',label:'0.75×'},{value:'1',label:'1× Normal'},
                    {value:'1.25',label:'1.25×'},{value:'1.5',label:'1.5×'},{value:'1.75',label:'1.75×'},{value:'2',label:'2×'}
                ], 'videoSpeedSelect');
                speed.select.value = '1'; mediaEl.playbackRate = 1;
                settingsRow.append(speed.wrap);
                panel.append(seek, timeRow, mainRow, settingsRow); container.appendChild(panel);

                const toggleVideoPlayback = () => { if (mediaEl.paused || mediaEl.ended) { if (mediaEl.ended) mediaEl.currentTime = 0; mediaEl.play().catch(() => {}); } else mediaEl.pause(); };
                togglePlaybackForShortcut = toggleVideoPlayback;
                play.onclick = toggleVideoPlayback;
                centerPlay.onclick = toggleVideoPlayback;
                mediaEl.addEventListener('play', () => { play.textContent = '❚❚ Pause'; centerPlay.textContent = '❚❚'; centerPlay.setAttribute('aria-label', 'Pause video'); centerPlay.title = 'Pause video'; centerPlay.classList.add('is-hidden'); });
                mediaEl.addEventListener('pause', () => { play.textContent = '▶ Play'; centerPlay.textContent = '▶'; centerPlay.setAttribute('aria-label', 'Play video'); centerPlay.title = 'Play video'; centerPlay.classList.remove('is-hidden'); });
                mediaEl.addEventListener('ended', () => { centerPlay.classList.remove('is-hidden'); centerPlay.textContent = '↻'; centerPlay.setAttribute('aria-label', 'Replay video'); centerPlay.title = 'Replay video'; });
                mediaEl.addEventListener('timeupdate', () => {
                    if (!seek.matches(':active') && mediaEl.duration) seek.value = String(Math.round(mediaEl.currentTime / mediaEl.duration * 1000));
                    currentTime.textContent = fmtTime(mediaEl.currentTime);
                });
                mediaEl.addEventListener('loadedmetadata', () => {
                    duration.textContent = fmtTime(mediaEl.duration);
                });
                seek.addEventListener('input', () => { if (mediaEl.duration) { mediaEl.currentTime = Number(seek.value) / 1000 * mediaEl.duration; currentTime.textContent = fmtTime(mediaEl.currentTime); } });
                speed.select.onchange = () => { mediaEl.playbackRate = Number(speed.select.value); };
                mediaEl.addEventListener('ratechange', () => { const rate = String(mediaEl.playbackRate); if ([...speed.select.options].some(o => o.value === rate)) speed.select.value = rate; });
                mute.onclick = () => { mediaEl.muted = !mediaEl.muted; mute.textContent = mediaEl.muted ? '🔇' : '🔊'; };
                volume.oninput = () => { mediaEl.volume = Number(volume.value); mediaEl.muted = mediaEl.volume === 0; mute.textContent = mediaEl.muted ? '🔇' : '🔊'; };
                fullscreen.onclick = () => {
                    // Fullscreen only the video. The browser's native controls appear in fullscreen,
                    // while the app header and oversized custom control panel stay outside it.
                    if (document.fullscreenElement === mediaEl) {
                        if (document.exitFullscreen) document.exitFullscreen().catch(() => {});
                        return;
                    }
                    mediaEl.controls = true;
                    if (mediaEl.requestFullscreen) {
                        mediaEl.requestFullscreen().catch(() => {
                            if (mediaEl.webkitEnterFullscreen) mediaEl.webkitEnterFullscreen();
                            else mediaEl.controls = false;
                        });
                    } else if (mediaEl.webkitEnterFullscreen) {
                        mediaEl.webkitEnterFullscreen();
                    } else {
                        mediaEl.controls = false;
                    }
                };
                mediaEl.addEventListener('fullscreenchange', () => {
                    if (!document.fullscreenElement) mediaEl.controls = false;
                });
                mediaEl.addEventListener('dblclick', () => { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); else if (stage.requestFullscreen) stage.requestFullscreen().catch(() => {}); });

            } else if (type === 'audio') {
                title.textContent = '🎵 Music Player — ' + displayName;
                mediaEl = document.createElement('audio'); mediaEl.src = url; mediaEl.controls = false;
                mediaEl.autoplay = false; mediaEl.preload = 'metadata'; mediaEl.className = 'media-player-audio';
                const artwork = document.createElement('div'); artwork.className = 'audio-artwork';
                const disc = document.createElement('div'); disc.className = 'audio-disc'; disc.textContent = '♫';
                const trackName = document.createElement('div'); trackName.className = 'audio-file-name'; trackName.textContent = name;
                const subtitle = document.createElement('div'); subtitle.style.cssText = 'color:#8ea0b8;font-size:12px'; subtitle.textContent = 'CYBER DRIVE • MUSIC';
                artwork.append(disc, trackName, subtitle); container.append(artwork);
                const panel = document.createElement('div'); panel.className = 'media-control-panel';
                const seek = document.createElement('input'); seek.type = 'range'; seek.min = '0'; seek.max = '1000'; seek.value = '0'; seek.className = 'media-seek'; seek.setAttribute('aria-label', 'Seek audio');
                const timeRow = document.createElement('div'); timeRow.className = 'media-time-row';
                const currentTime = document.createElement('span'); currentTime.textContent = '00:00'; const duration = document.createElement('span'); duration.textContent = '00:00'; timeRow.append(currentTime, duration);
                const row = document.createElement('div'); row.className = 'media-control-row'; row.style.justifyContent = 'center';
                const back = makeButton('↶ 10s'); const play = makeButton('▶ Play', 'primary'); const forward = makeButton('10s ↷'); const mute = makeButton('🔊');
                const volume = document.createElement('input'); volume.type = 'range'; volume.min = '0'; volume.max = '1'; volume.step = '0.05'; volume.value = '1'; volume.style.width = '90px'; volume.setAttribute('aria-label', 'Volume');
                const speed = makeSelect('Speed', [{value:'0.5',label:'0.5×'},{value:'0.75',label:'0.75×'},{value:'1',label:'1× Normal'},{value:'1.25',label:'1.25×'},{value:'1.5',label:'1.5×'},{value:'1.75',label:'1.75×'},{value:'2',label:'2×'}], 'audioSpeedSelect');
                speed.select.value = '1'; mediaEl.playbackRate = 1;
                row.append(back, play, forward, mute, volume, speed.wrap); panel.append(seek, timeRow, row); container.append(panel);
                const toggleAudioPlayback = () => { if (mediaEl.paused || mediaEl.ended) { if (mediaEl.ended) mediaEl.currentTime = 0; mediaEl.play().catch(() => {}); } else mediaEl.pause(); };
                togglePlaybackForShortcut = toggleAudioPlayback;
                play.onclick = toggleAudioPlayback;
                mediaEl.addEventListener('play', () => { play.textContent = '❚❚ Pause'; disc.classList.add('playing'); });
                mediaEl.addEventListener('pause', () => { play.textContent = '▶ Play'; disc.classList.remove('playing'); });
                mediaEl.addEventListener('timeupdate', () => { if (!seek.matches(':active') && mediaEl.duration) seek.value = String(Math.round(mediaEl.currentTime / mediaEl.duration * 1000)); currentTime.textContent = fmtTime(mediaEl.currentTime); });
                mediaEl.addEventListener('loadedmetadata', () => { duration.textContent = fmtTime(mediaEl.duration); });
                seek.addEventListener('input', () => { if (mediaEl.duration) { mediaEl.currentTime = Number(seek.value) / 1000 * mediaEl.duration; currentTime.textContent = fmtTime(mediaEl.currentTime); } });
                back.onclick = () => { mediaEl.currentTime = Math.max(0, mediaEl.currentTime - 10); };
                forward.onclick = () => { mediaEl.currentTime = Math.min(mediaEl.duration || Infinity, mediaEl.currentTime + 10); };
                mute.onclick = () => { mediaEl.muted = !mediaEl.muted; mute.textContent = mediaEl.muted ? '🔇' : '🔊'; };
                volume.oninput = () => { mediaEl.volume = Number(volume.value); mediaEl.muted = mediaEl.volume === 0; mute.textContent = mediaEl.muted ? '🔇' : '🔊'; };
                speed.select.onchange = () => { mediaEl.playbackRate = Number(speed.select.value); };
                mediaEl.addEventListener('ratechange', () => { const rate = String(mediaEl.playbackRate); if ([...speed.select.options].some(o => o.value === rate)) speed.select.value = rate; });
                container.appendChild(mediaEl);

            } else if (type === 'image') {
                title.textContent = '🖼️ Photo Viewer — ' + displayName;
                const stage = document.createElement('div'); stage.className = 'photo-stage';
                const img = document.createElement('img'); img.src = url; img.alt = name; img.className = 'photo-viewer-image'; img.style.transform = 'scale(1)'; stage.appendChild(img); container.appendChild(stage);
                const bar = document.createElement('div'); bar.className = 'media-control-panel';
                const row = document.createElement('div'); row.className = 'media-control-row'; row.style.justifyContent = 'center';
                const zoomOut = makeButton('− Zoom'); const zoomReset = makeButton('Fit to screen'); const zoomIn = makeButton('+ Zoom'); const rotate = makeButton('↻ Rotate');
                let scale = 1, angle = 0;
                const renderImage = () => { img.style.transform = `scale(${scale}) rotate(${angle}deg)`; img.style.maxWidth = scale > 1 ? 'none' : '100%'; img.style.maxHeight = scale > 1 ? 'none' : '68vh'; };
                zoomOut.onclick = () => { scale = Math.max(.25, scale - .25); renderImage(); };
                zoomIn.onclick = () => { scale = Math.min(4, scale + .25); renderImage(); };
                zoomReset.onclick = () => { scale = 1; angle = 0; renderImage(); stage.scrollTo({top:0,left:0,behavior:'smooth'}); };
                rotate.onclick = () => { angle = (angle + 90) % 360; renderImage(); };
                row.append(zoomOut, zoomReset, zoomIn, rotate); bar.append(row); container.appendChild(bar);
            } else if (type === 'code') {
                title.textContent = '⌨️ Code Viewer — ' + displayName;
                const ext = (name.match(/\.([^.]+)$/) || ['', 'text'])[1].toLowerCase();
                const viewer = document.createElement('div'); viewer.className = 'code-viewer'; viewer.dataset.theme = 'cyber';
                const toolbar = document.createElement('div'); toolbar.className = 'code-toolbar';
                const meta = document.createElement('span'); meta.className = 'code-meta'; meta.textContent = ext.toUpperCase() + ' • READ ONLY';
                const theme = document.createElement('select'); theme.className = 'code-select'; theme.setAttribute('aria-label', 'Code colour theme');
                [['cyber','Cyber Night'],['monokai','Monokai'],['light','Light']].forEach(([value,label]) => { const opt=document.createElement('option'); opt.value=value; opt.textContent=label; theme.appendChild(opt); });
                const smaller = makeButton('A−'), larger = makeButton('A+');
                const wrapToggle = makeButton('↩ Wrap lines: OFF', 'code-wrap-toggle');
                wrapToggle.id = 'codeWrapLinesToggle'; wrapToggle.setAttribute('aria-label', 'Toggle line wrapping'); wrapToggle.setAttribute('aria-pressed', 'false');
                let wrapEnabled = false;
                const copy = makeButton('⧉ Copy code');
                toolbar.append(meta, theme, smaller, larger, wrapToggle, copy);
                const scroll = document.createElement('div'); scroll.className='code-scroll';
                const lines = document.createElement('div'); lines.className='code-lines';
                const gutter = document.createElement('div'); gutter.className='code-gutter'; gutter.textContent='1';
                const pre = document.createElement('pre'); pre.className='code-source'; pre.style.fontSize='13px';
                lines.append(gutter, pre); scroll.appendChild(lines); viewer.append(toolbar, scroll); container.appendChild(viewer);
                const info = document.createElement('div'); info.className='code-info'; info.textContent='Read-only syntax-coloured preview • Choose a theme, adjust text size, copy the source, or enable line wrapping.'; container.appendChild(info);
                let sourceText = '';
                const escapeHtml = value => value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
                const renderCode = () => {
                    const keywords = new Set(('if else elif then end for while do break continue return function local const let var async await yield try catch finally throw raise except import from as class def lambda with pass True False None and or not in is global nonlocal assert del match case switch default goto sizeof typedef struct enum union static extern volatile register inline auto signed unsigned short long int float double char void bool true false null nullptr new delete this public private protected virtual override template typename using namespace include define ifdef ifndef endif pragma return void fn pub mod use impl trait mut self Self crate super match loop move where type let fn const static ref dyn async await struct enum impl trait package func defer go chan select map range interface string error fallthrough import export package var const nil true false false function end local require print pairs ipairs repeat until elseif nil self begin rescue ensure module puts puts! echo set export fi done esac case in then elif function local readonly declare select until do done exit break continue source alias cd pwd test read printf cat ls grep awk sed find xargs if for while elif else fi then return exit sql select insert update delete create alter drop table from where join on as group by order having limit offset distinct primary key foreign references not and or like null is begin commit rollback with recursive').split());
                    const hashComment = ['py','pyw','sh','bash','zsh','fish','rb','yaml','yml','toml','ini','cfg','conf','env','r','jl','pl','pm','makefile','mk','dockerfile','tex'].includes(ext) ? '|#[^\\n]*' : '';
                    const dashComment = ['lua','sql'].includes(ext) ? '|--[^\\n]*' : '';
                    const rx = new RegExp('(\\/\\*[\\s\\S]*?\\*\\/|<!--[\\s\\S]*?-->|\"(?:\\\\.|[^\"\\\\])*\"|\'(?:\\\\.|[^\'\\\\])*\'|`(?:\\\\.|[^`\\\\])*`|\\/\\/[^\\n]*' + hashComment + dashComment + '|\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b|\\b[A-Za-z_$][\\w$]*\\b|[^\\w\\s])', 'g');
                    let html = '', last = 0, match;
                    while ((match = rx.exec(sourceText)) !== null) {
                        html += escapeHtml(sourceText.slice(last, match.index));
                        const token = match[0]; let cls = '';
                        if (/^(\/\*|\/\/|<!--|#|--)/.test(token)) {
                            // Treat # as a comment marker only for languages that use it.
                            const hashIsComment = ['py','pyw','sh','bash','zsh','fish','rb','yaml','yml','toml','ini','conf','env','r','jl','pl','pm','makefile','mk','dockerfile','tex'].includes(ext);
                            if (token.startsWith('#') && !hashIsComment && ext !== 'ipynb') cls = 'tok-operator'; else cls = 'tok-comment';
                        } else if (/^["'`]/.test(token)) cls='tok-string';
                        else if (/^\d/.test(token)) cls='tok-number';
                        else if (/^[A-Za-z_$]/.test(token)) {
                            if (keywords.has(token)) cls='tok-keyword';
                            else if (/^[A-Z][A-Za-z0-9_]*$/.test(token)) cls='tok-type';
                            else if (/\bfunction\s+$/.test(sourceText.slice(Math.max(0,match.index-20),match.index))) cls='tok-function';
                        } else if (/^[+*/%=!<>|&^~?:.-]$/.test(token)) cls='tok-operator';
                        html += cls ? '<span class="'+cls+'">'+escapeHtml(token)+'</span>' : escapeHtml(token);
                        last = rx.lastIndex;
                    }
                    html += escapeHtml(sourceText.slice(last));
                    pre.innerHTML = html || ' ';
                    gutter.textContent = Array.from({length: Math.max(1, sourceText.split('\n').length)}, (_,i) => String(i+1)).join('\n');
                    pre.classList.toggle('wrap', wrapEnabled);
                    lines.classList.toggle('wrap', wrapEnabled);
                };
                theme.onchange = () => { viewer.dataset.theme=theme.value; };
                smaller.onclick = () => { pre.style.fontSize=Math.max(9,parseInt(pre.style.fontSize,10)-1)+'px'; };
                larger.onclick = () => { pre.style.fontSize=Math.min(24,parseInt(pre.style.fontSize,10)+1)+'px'; };
                wrapToggle.addEventListener('click', () => { wrapEnabled = !wrapEnabled; wrapToggle.setAttribute('aria-pressed', String(wrapEnabled)); wrapToggle.textContent = wrapEnabled ? '↩ Wrap lines: ON' : '↩ Wrap lines: OFF'; renderCode(); });
                copy.onclick = async () => { try { await navigator.clipboard.writeText(sourceText); copy.textContent='✓ Copied'; setTimeout(()=>copy.textContent='⧉ Copy code',1200); } catch (_) { info.textContent='Clipboard access was blocked by the browser. Select the code and copy it manually.'; } };
                const safePath = String(relPath || '').split('/').map(part => encodeURIComponent(part)).join('/');
                fetch('/api/code-preview/' + safePath, {credentials:'same-origin'})
                    .then(async response => { if (!response.ok) { let msg='Unable to open this file.'; try { const data=await response.json(); msg=data.error || msg; } catch (_) {} throw new Error(msg); } return response.text(); })
                    .then(text => { sourceText=text; renderCode(); meta.textContent=ext.toUpperCase()+' • '+sourceText.split('\n').length+' LINES • READ ONLY'; })
                    .catch(err => { sourceText=''; pre.textContent=err.message || 'Unable to load source file.'; gutter.textContent='1'; info.textContent='The source could not be loaded. Try downloading the file instead.'; });
            } else if (type === 'document') {
                title.textContent = '📚 Document Reader — ' + displayName;
                const ext = (name.split('.').pop() || '').toLowerCase();
                const isPdf = ext === 'pdf';
                const stage = document.createElement('div'); stage.className = 'document-stage';
                const frame = document.createElement('iframe'); frame.className = 'document-frame';
                frame.title = 'Document reader: ' + name;
                frame.loading = 'lazy';
                const safePath = String(relPath || '').split('/').map(part => encodeURIComponent(part)).join('/');
                frame.src = '/api/document-preview/' + safePath;
                stage.appendChild(frame); container.appendChild(stage);
                const info = document.createElement('div'); info.className = 'document-info';
                info.textContent = isPdf
                    ? 'PDF document • Use the built-in PDF controls to search, zoom, print, or navigate pages. Full screen is available above.'
                    : 'Office document • Converted to a read-only PDF preview on this server. Tables, slides, and page layout are preserved where supported. Full screen is available above.';
                container.appendChild(info);
            }
            if ((type === 'video' || type === 'audio') && mediaEl) {
                showKeyHint('Shortcut: Space Play/Pause');
                mediaKeyboardHandler = event => {
                    if (!document.getElementById('mediaModal').classList.contains('active')) return;
                    const target = event.target;
                    const tag = target && target.tagName ? target.tagName.toLowerCase() : '';
                    if (['input','textarea','select','button'].includes(tag) || (target && target.isContentEditable)) return;
                    if (event.code === 'Space' || event.key === ' ') {
                        event.preventDefault(); if (togglePlaybackForShortcut) togglePlaybackForShortcut();
                    }
                };
                document.addEventListener('keydown', mediaKeyboardHandler);
            }
            showModal('mediaModal');
        }

        const toggleMediaFullscreen = () => {
            // Music playback intentionally stays inside the regular media dialog.
            if (document.getElementById('mediaTitleText')?.textContent?.startsWith('🎵 Music Player')) return;
            const card = document.querySelector('#mediaModal .media-modal-card');
            if (!document.fullscreenElement) {
                if (card.requestFullscreen) card.requestFullscreen().catch(() => {});
            } else if (document.exitFullscreen) {
                document.exitFullscreen().catch(() => {});
            }
        };
        document.getElementById('btnMediaFullscreen').onclick = toggleMediaFullscreen;
        document.addEventListener('fullscreenchange', () => {
            const b = document.getElementById('btnMediaFullscreen');
            b.textContent = document.fullscreenElement ? '⤢ Exit full screen' : '⛶ Full screen';
        });

        const closeMedia = () => {
            if (mediaKeyboardHandler) { document.removeEventListener('keydown', mediaKeyboardHandler); mediaKeyboardHandler = null; }
            const container = document.getElementById('mediaContainer');
            container.querySelectorAll('iframe').forEach(frame => { frame.src = 'about:blank'; });
            container.innerHTML = '';
            if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(() => {});
            hideModal('mediaModal');
        };
        document.getElementById('btnCloseMediaTop').onclick = closeMedia;
        document.getElementById('btnCloseMediaBottom').onclick = closeMedia;
    </script>
</body>
</html>
"""

def load_users():
    """Load the account database safely, including a fresh/empty installation.

    A missing or zero-byte users.json means there are currently no registered
    accounts. Do not resurrect a deleted database from .bak/.tmp automatically:
    an administrator may have intentionally reset the account list.
    Invalid non-empty JSON is logged and left untouched for manual recovery.
    """
    os.makedirs(os.path.dirname(USERS_FILE) or '.', exist_ok=True)

    if not os.path.exists(USERS_FILE):
        # Create a valid empty database atomically. If another worker creates it
        # first, simply read the file on the next request.
        temp_path = USERS_FILE + '.init.tmp'
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write('{}\n')
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(temp_path, USERS_FILE)  # do not overwrite a concurrent creation
            except FileExistsError:
                pass
        except OSError:
            app.logger.exception('Could not initialize an empty account database')
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except OSError:
                pass

    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            raw = f.read()
        if not raw.strip():
            # Treat an empty file as an empty account database; the next account
            # save will replace it with valid JSON.
            return {}
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
        app.logger.error('Account database root must be a JSON object; treating it as empty')
        return {}
    except FileNotFoundError:
        # Rare race: the file was removed between initialization and opening.
        return {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        app.logger.exception('Could not read users.json; treating account database as empty')
        return {}

def get_folder_size(folder_path):
    total_size = 0
    if os.path.exists(folder_path):
        for dirpath, dirnames, filenames in os.walk(folder_path, followlinks=False):
            # Do not count or follow symlinks that could point outside the user's area.
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    if not os.path.islink(fp) and os.path.isfile(fp):
                        total_size += os.path.getsize(fp)
                except OSError:
                    continue
    return total_size

def get_unique_filename(target_dir, filename):
    if not os.path.exists(os.path.join(target_dir, filename)):
        return filename
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(os.path.join(target_dir, f"{base}({counter}){ext}")):
        counter += 1
    return f"{base}({counter}){ext}"

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # A signed session cookie is not proof that the account still exists.
        # In particular, after users.json is reset, old browser sessions must not
        # continue into the drive as a deleted/missing user.
        username = session.get('username')
        if not session.get('authenticated') or not username:
            session.clear()
            return redirect(url_for('login'))

        try:
            users = load_users()
            account = users.get(username) if isinstance(users, dict) else None
        except Exception:
            app.logger.exception('Could not refresh authenticated account state')
            session.clear()
            return redirect(url_for('login'))

        if not isinstance(account, dict):
            session.clear()
            return redirect(url_for('login'))

        # Refresh the storage folder from the canonical account record.
        folder = safe_folder_name(account.get('folder', ''))
        if not folder:
            session.clear()
            return redirect(url_for('login'))
        session['user_folder'] = folder
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/code-preview/<path:req_path>')
@login_required
def code_preview(req_path):
    """Serve small text/source files to the authenticated read-only Code Viewer."""
    user_folder_name = session.get('user_folder', '')
    user_root = user_root_path(user_folder_name)
    abs_path = resolve_user_path(user_root, req_path)
    if os.path.islink(abs_path) or not os.path.isfile(abs_path):
        abort(404)
    ext = os.path.splitext(abs_path)[1].lower()
    if ext not in {e.lower() for e in CODE_EXTS}:
        abort(415)
    try:
        size = os.path.getsize(abs_path)
        if size > 2 * 1024 * 1024:
            return jsonify({'error': 'Code Viewer previews are limited to 2 MB. Download this file to inspect it.'}), 413
        with open(abs_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as source_file:
            source = source_file.read(2 * 1024 * 1024 + 1)
        if len(source.encode('utf-8', errors='replace')) > 2 * 1024 * 1024:
            return jsonify({'error': 'Code Viewer previews are limited to 2 MB. Download this file to inspect it.'}), 413
        response = app.response_class(source, mimetype='text/plain; charset=utf-8')
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Disposition'] = 'inline; filename="' + secure_filename(os.path.basename(abs_path)) + '"'
        return response
    except OSError:
        app.logger.exception('Could not read source file for Code Viewer')
        return jsonify({'error': 'The server could not read this source file.'}), 500


@app.route('/api/document-preview/<path:req_path>')
@login_required
def document_preview(req_path):
    """Convert supported Office files to a temporary PDF for in-app reading."""
    user_folder_name = session.get('user_folder', '')
    user_root = user_root_path(user_folder_name)
    abs_path = resolve_user_path(user_root, req_path)
    if os.path.islink(abs_path) or not os.path.isfile(abs_path):
        abort(404)
    ext = os.path.splitext(abs_path)[1].lower()
    if ext == '.pdf':
        response = send_file(abs_path, mimetype='application/pdf', as_attachment=False, download_name=os.path.basename(abs_path))
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
        return response
    if ext not in OFFICE_DOCUMENT_EXTS:
        abort(415)
    soffice = shutil.which('libreoffice') or shutil.which('soffice')
    if not soffice:
        return jsonify({'error': 'Office document previews require LibreOffice on the Cyber Drive server. You can still download this file.'}), 501

    try:
        with tempfile.TemporaryDirectory(prefix='cyberdrive-doc-') as temp_dir:
            profile_dir = os.path.join(temp_dir, 'profile')
            out_dir = os.path.join(temp_dir, 'out')
            os.makedirs(out_dir, exist_ok=True)
            result = subprocess.run(
                [soffice, '-env:UserInstallation=' + Path(profile_dir).as_uri(), '--headless', '--convert-to', 'pdf', '--outdir', out_dir, abs_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False
            )
            pdf_path = os.path.join(out_dir, os.path.splitext(os.path.basename(abs_path))[0] + '.pdf')
            if result.returncode != 0 or not os.path.isfile(pdf_path):
                app.logger.warning('Document preview conversion failed for %s: %s', os.path.basename(abs_path), result.stderr.decode('utf-8', 'replace')[-1000:])
                return jsonify({'error': 'This document could not be converted for preview. Try downloading it or saving it in a newer Office format.'}), 422
            with open(pdf_path, 'rb') as f:
                pdf_bytes = f.read()
        response = send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=False, download_name=os.path.splitext(os.path.basename(abs_path))[0] + '.pdf')
        response.headers['Cache-Control'] = 'private, no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
        return response
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Document preview took too long. Try a smaller file or download it instead.'}), 504
    except OSError:
        app.logger.exception('Could not generate document preview')
        return jsonify({'error': 'The server could not generate this document preview.'}), 500


@app.route('/cloud-icon.svg')
def cloud_icon():
    """Serve the user's actual SVG logo instead of drawing a placeholder icon.

    Put the logo at static/logo.svg (recommended), or beside this Python file
    as logo.svg / cloud-icon.svg. The route keeps all existing page references
    working, including references with a cache-busting query string.
    """
    logo_candidates = (
        os.path.join(app.static_folder or os.path.join(APP_DIR, 'static'), 'logo.svg'),
        os.path.join(app.static_folder or os.path.join(APP_DIR, 'static'), 'cloud-icon.svg'),
        os.path.join(APP_DIR, 'logo.svg'),
        os.path.join(APP_DIR, 'cloud-icon.svg'),
    )
    logo_path = next((candidate for candidate in logo_candidates if os.path.isfile(candidate)), None)
    if logo_path is None:
        app.logger.error(
            'Cyber Drive SVG logo not found. Put your existing SVG at %s',
            os.path.join(app.static_folder or os.path.join(APP_DIR, 'static'), 'logo.svg')
        )
        return 'Logo SVG not found. Put your logo at static/logo.svg beside the app.', 404

    response = send_file(logo_path, mimetype='image/svg+xml', conditional=False, max_age=0)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# --- BULK DOWNLOAD API ROUTE (BUNDLES ALL SELECTED ITEMS INTO A ZIP) ---
@app.route('/api/bulk-download', methods=['POST'])
@login_required
def bulk_download():
    user_folder_name = session.get('user_folder', 'HI')
    user_root = user_root_path(user_folder_name)
    
    items_to_zip = request.form.getlist('item_path')
    if not items_to_zip:
        return jsonify({'error': 'No items selected'}), 400

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_STORED) as zf:
        for rel_p in items_to_zip:
            abs_p = resolve_user_path(user_root, rel_p)
            if not os.path.exists(abs_p) or os.path.islink(abs_p):
                continue
            
            arcname = os.path.basename(abs_p)
            if os.path.isfile(abs_p):
                zf.write(abs_p, arcname)
            elif os.path.isdir(abs_p):
                for root, dirs, files in os.walk(abs_p, followlinks=False):
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.islink(file_path) or not os.path.isfile(file_path):
                            continue
                        rel_path = os.path.relpath(file_path, os.path.dirname(abs_p))
                        zf.write(file_path, rel_path)

    memory_file.seek(0)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name='selected_files.zip'
    )

@app.route('/api/sync-files')
@login_required
def sync_files():
    """Return a fresh listing and storage totals for live multi-device refresh."""
    user_folder_name = session.get('user_folder', 'HI')
    user_root = user_root_path(user_folder_name)
    req_path = request.args.get('path', '')
    abs_path = resolve_user_path(user_root, req_path)
    if not os.path.isdir(abs_path) or os.path.islink(abs_path):
        return jsonify({'error': 'Folder no longer exists.'}), 404
    try:
        raw_items = os.listdir(abs_path)
    except OSError:
        return jsonify({'error': 'Unable to read this folder.'}), 500

    items = []
    for name in sorted(raw_items, key=str.casefold):
        if name.startswith('.'):
            continue
        full_path = os.path.join(abs_path, name)
        if os.path.islink(full_path):
            continue
        is_dir = os.path.isdir(full_path)
        rel_path = os.path.relpath(full_path, user_root).replace('\\', '/')
        ext = os.path.splitext(name)[1].lower()
        media_type = 'image' if ext in IMAGE_EXTS else 'audio' if ext in AUDIO_EXTS else 'video' if ext in VIDEO_EXTS else 'document' if ext in DOCUMENT_EXTS else 'code' if ext in {e.lower() for e in CODE_EXTS} else None
        size_bytes = get_folder_size(full_path) if is_dir else os.path.getsize(full_path)
        items.append({
            'name': name,
            'rel_path': rel_path,
            'file_url': url_for('browse_files', req_path=rel_path),
            'is_dir': is_dir,
            'size_str': format_size(size_bytes),
            'media_type': media_type,
        })

    used_bytes = get_folder_size(user_root)
    user_record = load_users().get(session.get('username', ''), {})
    quota_bytes = effective_user_quota(user_record)
    storage_pct = min(100, int((used_bytes / quota_bytes) * 100))
    pending_requests = load_storage_requests()
    response = jsonify({
        'items': items,
        'used_gb': round(used_bytes / (1024 * 1024 * 1024), 2),
        'storage_pct': storage_pct,
        'quota_gb': round(quota_bytes / (1024 * 1024 * 1024), 3),
        'quota_approved_at': str(user_record.get('quota_approved_at') or ''),
        'storage_request_pending': session.get('username', '') in pending_requests,
        'server_time': int(os.path.getmtime(abs_path) * 1000),
    })
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/api/list-folders/', defaults={'req_path': ''})
@app.route('/api/list-folders/<path:req_path>')
@login_required
def list_folders(req_path=''):
    user_folder_name = session.get('user_folder', 'HI')
    user_root = user_root_path(user_folder_name)
    abs_path = resolve_user_path(user_root, req_path)

    if not os.path.exists(abs_path) or not os.path.isdir(abs_path) or os.path.islink(abs_path):
        return jsonify({'error': 'Invalid path'}), 400

    folders = []
    try:
        for item in sorted(os.listdir(abs_path)):
            if item.startswith('.'):
                continue
            full_p = os.path.join(abs_path, item)
            if os.path.isdir(full_p):
                rel_p = os.path.relpath(full_p, user_root)
                folders.append({
                    'name': item,
                    'rel_path': rel_p.replace('\\', '/')
                })
    except OSError:
        return jsonify({'error': 'Unable to read this folder.'}), 500

    parent_rel = None
    if abs_path != user_root:
        parent_p = os.path.dirname(abs_path)
        p_rel = os.path.relpath(parent_p, user_root)
        parent_rel = '' if p_rel == '.' else p_rel.replace('\\', '/')

    display_path = clean_path_display(req_path, 'Home')

    return jsonify({
        'current_rel': req_path.replace('\\', '/'),
        'display_path': display_path,
        'user_root_name': 'Home',
        'parent_rel': parent_rel,
        'folders': folders
    })

@app.route('/api/mkv-subtitles/<path:req_path>')
@login_required
def mkv_subtitles(req_path):
    user_root = user_root_path(session['user_folder'])
    abs_path = resolve_user_path(user_root, req_path)

    if not os.path.isfile(abs_path) or os.path.islink(abs_path):
        return jsonify({'error': 'Invalid path'}), 400

    stream_idx = request.args.get('stream', '0:s:0')
    if not re.fullmatch(r'0:s:\d{1,3}', stream_idx):
        return jsonify({'error': 'Invalid subtitle stream.'}), 400
    cmd = ['ffmpeg', '-nostdin', '-v', 'error', '-i', abs_path, '-map', stream_idx, '-f', 'webvtt', '-']

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout, 200, {'Content-Type': 'text/vtt'}
    except Exception:
        pass

    return "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\nSubtitles unavailable or none embedded.", 200, {'Content-Type': 'text/vtt'}


AUTH_TEMPLATE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{ csrf_token() }}"><link rel="icon" type="image/svg+xml" href="/cloud-icon.svg?v=3"><title>Cyber Drive — Account</title>
<style>
*{box-sizing:border-box;font-family:'Courier New',monospace}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top,#14223a,#07090e 70%);color:#e2e8f0;padding:20px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:8px}.brand img{width:38px;height:38px;display:block;object-fit:contain}.card{width:min(440px,100%);padding:28px;background:rgba(17,24,39,.92);border:1px solid rgba(0,240,255,.25);border-radius:18px;box-shadow:0 22px 70px #0008;animation:enter .35s cubic-bezier(.16,1,.3,1)}
@keyframes enter{from{opacity:0;transform:translateY(14px) scale(.98)}to{opacity:1;transform:none}}
h1{font-size:24px;color:#00f0ff;margin:0 0 8px}p{color:#94a3b8;font-size:13px;line-height:1.5}.tabs{display:flex;gap:8px;margin:20px 0}.tabs a{flex:1;text-align:center;text-decoration:none;padding:10px;border:1px solid #334155;border-radius:9px;color:#94a3b8}.tabs a.active{background:#00e5ff;color:#06111c;border-color:#00e5ff;font-weight:bold}.tabs a.disabled-signup{opacity:.55;cursor:not-allowed;border-style:dashed}.tabs a.disabled-signup:hover::after{content:' · Max users reached';font-size:11px}
label{display:block;color:#94a3b8;font-size:12px;margin:12px 0 6px}input{width:100%;min-width:0;padding:12px;background:#080d17;border:1px solid #334155;border-radius:8px;color:#fff;font-size:14px}input:focus{outline:2px solid #00e5ff;border-color:transparent}.secret-wrap{position:relative;width:100%;display:block}.secret-wrap input{padding-right:46px}.secret-wrap .secret-eye{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:34px!important;height:34px!important;min-width:34px;margin:0!important;padding:0!important;display:grid;place-items:center;background:transparent!important;border:0!important;border-radius:6px;color:#94a3b8;cursor:pointer;box-shadow:none!important;font-size:0!important}.secret-wrap .secret-eye:hover{color:#00e5ff;background:#122033!important}.secret-eye svg{width:19px;height:19px;display:block}
button,.primary{width:100%;display:block;padding:12px;border:0;border-radius:8px;background:linear-gradient(120deg,#00e5ff,#3b82f6);color:#06111c;font-weight:bold;font-size:14px;cursor:pointer;text-align:center;text-decoration:none;margin-top:14px}
#resendOtpButton{background:transparent;color:#67e8f9;border:1px solid #334155;box-shadow:none;transition:border-color .2s,color .2s,background .2s}
#resendOtpButton:disabled{color:#64748b;border-color:#263448;cursor:not-allowed;opacity:.85}
#resendOtpButton:not(:disabled):hover{border-color:#67e8f9;background:#08334455}
.google{background:#111827;border:1px solid #475569;color:#e2e8f0}.error{padding:10px;background:#7f1d1d33;border:1px solid #f87171;color:#fca5a5;border-radius:8px;font-size:13px;margin:12px 0}.success{padding:10px;background:#064e3b44;border:1px solid #34d399;color:#a7f3d0;border-radius:8px;font-size:13px;margin:12px 0}.small{text-align:center;font-size:12px}.small a{color:#67e8f9}.hidden{display:none}
</style></head><body><main class="card"><div class="brand"><img src="/cloud-icon.svg?v=3" alt="Cyber Drive logo"><h1>Cyber Drive</h1></div><p>{{ subtitle }}</p>
{% if error %}<div class="error">{{ error }}</div>{% endif %}{% if message %}<div class="success">{{ message }}</div>{% endif %}
{% if page in ['login','signup','verify_signup'] %}
<div class="tabs"><a href="/" class="{{ 'active' if page=='login' else '' }}">Log in</a>{% if signup_full %}<a href="/signup" class="disabled-signup" aria-disabled="true" title="Maximum users reached" onclick="alert('Maximum users reached — sorry, Cyber Drive currently supports only 5 client accounts.');return false;">Create account</a>{% else %}<a href="/signup" class="{{ 'active' if page=='signup' else '' }}">Create account</a>{% endif %}</div>{% if signup_full and page=='signup' %}<div class="error" role="status">Maximum users reached — sorry, Cyber Drive currently supports only 5 client accounts. Please try again when registration reopens.</div>{% endif %}
{% if page=='login' %}
<form method="post" action="/"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<label>Email address or username</label><input name="identity" required autocomplete="username" value="{{ identity or '' }}">
<label>Password</label><input type="password" name="password" required autocomplete="current-password">
<button type="submit">Log in</button></form><p class="small"><a href="/forgot-password">Forgot password?</a></p>
{% elif page=='verify_signup' %}
<form method="post" action="/verify-signup"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<label>6-digit code sent to {{ email }}</label><input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
<button type="submit">Verify email and create account</button></form>
<p class="small" id="otpExpiryMessage">Code expires in <strong id="otpExpiry">02:00</strong>.</p>
<p class="small" id="resendTimerMessage" aria-live="polite">Resend available in <strong id="resendCountdown">00:30</strong>...</p>
<form method="post" action="/resend-signup-otp"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button id="resendOtpButton" type="submit" disabled>Resend OTP</button></form>
<p class="small"><a href="/signup?restart=1">Change details / start again</a></p>
<script>
(function(){
 const expiresAt={{ otp_expires_at|default(0)|tojson }}*1000;
 const resendAt={{ otp_resend_at|default(0)|tojson }}*1000;
 const expiry=document.getElementById('otpExpiry'), countdown=document.getElementById('resendCountdown'), button=document.getElementById('resendOtpButton');
 const fmt=n=>{n=Math.max(0,Math.ceil(n/1000));return String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0')};
 let expiryHandled=false;
 function tick(){
   const now=Date.now();
   if(now>=expiresAt){
     if(!expiryHandled){
       expiryHandled=true;
       document.getElementById('otpExpiryMessage').textContent='Code expired. Redirecting...';
       document.querySelectorAll('form').forEach(form=>form.querySelectorAll('input,button').forEach(el=>el.disabled=true));
       window.setTimeout(()=>{ window.location.href='/signup?restart=1'; },2000);
     }
     return;
   }
   expiry.textContent=fmt(expiresAt-now);
   const remain=resendAt-now;
   const timerMessage=document.getElementById('resendTimerMessage');
   if(remain>0){
     button.disabled=true;
     countdown.textContent=fmt(remain);
     timerMessage.style.display='block';
   }else{
     button.disabled=false;
     countdown.textContent='00:00';
     timerMessage.textContent='You can request a new code now.';
   }
 }
 tick();setInterval(tick,250);
})();
</script>
{% else %}
<form method="post" action="/signup"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<label>Your name (used for your home folder)</label><input name="display_name" required maxlength="60" autocomplete="name" value="{{ display_name or '' }}" {% if signup_full %}disabled title="Maximum users reached"{% endif %}>
<label>Email address</label><input type="email" name="email" required autocomplete="email" value="{{ email or '' }}" {% if signup_full %}disabled title="Maximum users reached"{% endif %}>
<label>Password (at least 10 characters)</label><input type="password" name="password" required minlength="10" autocomplete="new-password" {% if signup_full %}disabled title="Maximum users reached"{% endif %}>
<label>Confirm password</label><input type="password" name="confirm_password" required minlength="10" autocomplete="new-password" {% if signup_full %}disabled title="Maximum users reached"{% endif %}>
<button type="submit" {% if signup_full %}disabled title="Maximum users reached"{% endif %}>Send verification code</button></form>
{% endif %}
{% if page != 'verify_signup' %}<p class="small">Google login not available.</p>{% endif %}
{% elif page=='forgot' %}
{% if not otp_sent %}<form method="post" action="/forgot-password"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<label>Account email</label><input type="email" name="email" required autocomplete="email">
<button type="submit">Send one-time code</button></form>{% endif %}
{% if otp_sent %}<p class="small">Enter the code sent to your registered email address.</p><form method="post" action="/reset-password"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<label>6-digit email code</label><input name="otp" inputmode="numeric" pattern="[0-9]{6}" required>
<label>New password</label><input type="password" name="password" minlength="10" required autocomplete="new-password">
<label>Confirm new password</label><input type="password" name="confirm_password" minlength="10" required autocomplete="new-password">
<button type="submit">Reset password</button></form>{% endif %}
<p class="small"><a href="/">Back to login</a></p>
{% endif %}<script>
(function(){
 // Only focus the one-time verification code. Never autofocus login fields: this
 // avoids immediately opening a browser-saved-password dropdown after logout.
 function focusOtpOnly(){
   const otp=document.querySelector('input[name="otp"]:not([disabled])');
   if(otp && otp.offsetParent!==null){otp.focus({preventScroll:true}); otp.select();}
 }
 if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',focusOtpOnly,{once:true}); else focusOtpOnly();
 // Enter submits the current form from any ordinary input (OTP included).
 document.addEventListener('keydown',function(event){
   if(event.key!=='Enter' || event.isComposing) return;
   const field=event.target;
   if(!(field instanceof HTMLInputElement) || field.type==='submit' || field.type==='button' || field.type==='checkbox') return;
   const form=field.form;
   if(!form) return;
   event.preventDefault();
   if(typeof form.requestSubmit==='function') form.requestSubmit();
   else form.submit();
 });
 const eyeSvg='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
 const hideSvg='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a16 16 0 0 1-3.1 3.9"/><path d="M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7c1.3 0 2.5-.3 3.5-.8"/></svg>';
 document.querySelectorAll('input[type="password"],input[name="otp"]').forEach(function(input){
   if(input.dataset.eyeReady) return; input.dataset.eyeReady='1';
   const wrap=document.createElement('span');wrap.className='secret-wrap';input.parentNode.insertBefore(wrap,input);wrap.appendChild(input);
   const btn=document.createElement('button');btn.type='button';btn.className='secret-eye';btn.innerHTML=eyeSvg;btn.title='Show value';btn.setAttribute('aria-label','Show value');btn.setAttribute('aria-pressed','false');
   btn.addEventListener('click',function(){const show=input.type==='password';input.type=show?'text':'password';btn.innerHTML=show?hideSvg:eyeSvg;btn.title=show?'Hide value':'Show value';btn.setAttribute('aria-label',show?'Hide value':'Show value');btn.setAttribute('aria-pressed',String(show));});
   wrap.appendChild(btn);
 });
})();
</script></main></body></html>
"""

def load_admin_settings():
    """Load adjustable policy settings, falling back safely if absent/corrupt."""
    defaults = {"max_accounts": 5, "base_storage_gb": 1, "max_cloud_storage_gb": 10, "last_effective_cloud_storage_bytes": None}
    try:
        with open(ADMIN_SETTINGS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            defaults['max_accounts'] = max(1, min(10000, int(data.get('max_accounts', defaults['max_accounts']))))
            defaults['base_storage_gb'] = max(1, min(5, int(data.get('base_storage_gb', defaults['base_storage_gb']))))
            defaults['max_cloud_storage_gb'] = max(1, int(data.get('max_cloud_storage_gb', defaults['max_cloud_storage_gb'])))
            try: defaults['last_effective_cloud_storage_bytes'] = int(data['last_effective_cloud_storage_bytes']) if data.get('last_effective_cloud_storage_bytes') is not None else None
            except (ValueError, TypeError): defaults['last_effective_cloud_storage_bytes'] = None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return defaults


def save_admin_settings(settings):
    os.makedirs(ADMIN_DIR, mode=0o700, exist_ok=True)
    temp_path = ADMIN_SETTINGS_FILE + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, ADMIN_SETTINGS_FILE)
    try: os.chmod(ADMIN_SETTINGS_FILE, 0o600)
    except OSError: pass


def cloud_usage_bytes():
    """Count files inside Cyber Drive account folders only, never unrelated server files."""
    users = load_users()
    total = 0
    for user in users.values():
        if not isinstance(user, dict):
            continue
        folder = safe_folder_name(user.get('folder', ''))
        if folder:
            total += get_folder_size(user_root_path(folder))
    return total


def effective_cloud_storage_limit_bytes(settings=None):
    """Apply the admin's configured cap and preserve at least 1 GiB of real disk free space."""
    settings = settings or load_admin_settings()
    configured = int(settings.get('max_cloud_storage_gb', 10)) * 1024**3
    try:
        disk_free = shutil.disk_usage(BASE_STORAGE_DIR).free
    except OSError:
        return configured
    # The filesystem's free-space figure already includes space occupied by Cyber Drive.
    # Add Cyber Drive's own stored bytes back so only unrelated system usage shrinks the cap.
    cloud_used = cloud_usage_bytes()
    free_before_cloud_data = disk_free + cloud_used
    safety_reserve = 1 * 1024**3
    system_ceiling = max(0, free_before_cloud_data - safety_reserve)
    return min(configured, system_ceiling)


def enforce_dynamic_cloud_limit():
    """Record automatic cap shrinkage when other server workloads consume free disk."""
    settings = load_admin_settings()
    effective = effective_cloud_storage_limit_bytes(settings)
    configured = settings['max_cloud_storage_gb'] * 1024**3
    previous = settings.get('last_effective_cloud_storage_bytes')
    if previous is not None:
        try: previous = int(previous)
        except (TypeError, ValueError): previous = None
    if previous is not None and effective < previous:
        old_gb = round(previous / 1024**3, 2)
        new_gb = round(effective / 1024**3, 2)
        record_admin_event('Automatic cloud storage cap reduction', f'{old_gb} GB -> {new_gb} GB because available system disk space decreased')
    settings['last_effective_cloud_storage_bytes'] = effective
    try: save_admin_settings(settings)
    except OSError: app.logger.exception('Could not persist effective cloud storage cap')
    return effective


def reserve_upload(username, size_bytes):
    """Atomically reserve quota for an upload before showing it as active to the user."""
    if size_bytes <= 0:
        raise ValueError('The selected upload is empty.')
    with UPLOAD_RESERVATION_LOCK:
        now = time.time()
        # Clear abandoned reservations (e.g. browser closed before cancellation request reached us).
        for token, item in list(UPLOAD_RESERVATIONS.items()):
            if now - item.get('created', now) > 6 * 60 * 60:
                UPLOAD_RESERVATIONS.pop(token, None)
        users = load_users()
        user = users.get(username, {})
        folder = safe_folder_name(user.get('folder', '')) if isinstance(user, dict) else ''
        used_user = get_folder_size(user_root_path(folder)) if folder else 0
        pending_user = sum(x['bytes'] for x in UPLOAD_RESERVATIONS.values() if x['username'] == username)
        quota = effective_user_quota(user) if isinstance(user, dict) else 0
        if used_user + pending_user + size_bytes > quota:
            reason = f'Not enough account storage after pending uploads. Used: {used_user/1024**3:.2f} GB; reserved: {pending_user/1024**3:.2f} GB; selected: {size_bytes/1024**3:.2f} GB; quota: {quota/1024**3:.2f} GB.'
            app.logger.warning('UPLOAD REJECTED BEFORE START | account=%s | reason=account_quota | used=%.3f GB | reserved=%.3f GB | selected=%.3f GB | quota=%.3f GB', username, used_user/1024**3, pending_user/1024**3, size_bytes/1024**3, quota/1024**3)
            raise ValueError(reason)
        used_cloud = cloud_usage_bytes()
        pending_cloud = sum(x['bytes'] for x in UPLOAD_RESERVATIONS.values())
        cloud_limit = enforce_dynamic_cloud_limit()
        if used_cloud + pending_cloud + size_bytes > cloud_limit:
            reason = f'Cyber Drive server storage is insufficient after pending uploads. Available cloud allocation: {max(0, cloud_limit-used_cloud-pending_cloud)/1024**3:.2f} GB.'
            app.logger.warning('UPLOAD REJECTED BEFORE START | account=%s | reason=cloud_quota | used=%.3f GB | reserved=%.3f GB | selected=%.3f GB | effective_cap=%.3f GB', username, used_cloud/1024**3, pending_cloud/1024**3, size_bytes/1024**3, cloud_limit/1024**3)
            raise ValueError(reason)
        token = secrets.token_urlsafe(24)
        UPLOAD_RESERVATIONS[token] = {'username': username, 'bytes': size_bytes, 'created': now}
        app.logger.info('UPLOAD RESERVED | account=%s | size=%.3f GB | user_used=%.3f GB | user_reserved_before=%.3f GB | quota=%.3f GB | cloud_used=%.3f GB | cloud_reserved_before=%.3f GB | cloud_cap=%.3f GB', username, size_bytes/1024**3, used_user/1024**3, pending_user/1024**3, quota/1024**3, used_cloud/1024**3, pending_cloud/1024**3, cloud_limit/1024**3)
        return token


def release_upload_reservation(token, username=None):
    if not token:
        return
    with UPLOAD_RESERVATION_LOCK:
        item = UPLOAD_RESERVATIONS.get(token)
        if item and (username is None or item.get('username') == username):
            UPLOAD_RESERVATIONS.pop(token, None)
            app.logger.info('UPLOAD RESERVATION RELEASED | account=%s | reserved=%.3f GB', item.get('username', 'unknown'), item.get('bytes', 0)/1024**3)


def record_admin_event(action, details=''):
    """Persist a small, private audit trail for admin sign-ins and actions."""
    try:
        os.makedirs(ADMIN_DIR, mode=0o700, exist_ok=True)
        try:
            with open(ADMIN_AUDIT_FILE, 'r', encoding='utf-8') as f:
                events = json.load(f)
            if not isinstance(events, list):
                events = []
        except (OSError, ValueError, json.JSONDecodeError):
            events = []
        events.append({
            'time': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'admin': str(session.get('admin_username') or 'anonymous'),
            'action': str(action)[:120],
            'details': str(details)[:500],
            'ip': str(request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')).split(',')[0].strip()[:80],
        })
        with open(ADMIN_AUDIT_FILE + '.tmp', 'w', encoding='utf-8') as f:
            json.dump(events[-500:], f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(ADMIN_AUDIT_FILE + '.tmp', ADMIN_AUDIT_FILE)
        try: os.chmod(ADMIN_AUDIT_FILE, 0o600)
        except OSError: pass
    except OSError:
        app.logger.exception('Could not write admin audit event')


def load_admin_events(limit=200):
    """Return newest-first admin audit entries from the last 10 days only."""
    try:
        with open(ADMIN_AUDIT_FILE, 'r', encoding='utf-8') as f:
            events = json.load(f)
        if not isinstance(events, list):
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=10)
        recent = []
        for event in events:
            if not isinstance(event, dict):
                continue
            try:
                stamp = datetime.fromisoformat(str(event.get('time', '')).replace('Z', '+00:00'))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                if stamp >= cutoff:
                    recent.append(event)
            except (TypeError, ValueError):
                continue
        return list(reversed(recent[-max(1, min(500, int(limit))):]))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return []


def current_base_storage_bytes():
    return load_admin_settings()['base_storage_gb'] * 1024**3


def user_account_limit_reached(users):
    """Return True once the configured number of regular profiles exists."""
    limit = load_admin_settings()['max_accounts']
    return sum(1 for record in users.values() if isinstance(record, dict)) >= limit

def signup_cap_message():
    limit = load_admin_settings()['max_accounts']
    return (f"We sincerely apologize for the inconvenience. Cyber Drive has currently reached "
            f"its limit of {limit} user accounts. We will soon be back with more storage and space "
            "for you to create your own space. Thank you for your patience.")

# Kept as a compatibility name for existing routes; generated dynamically where possible.
SIGNUP_CAP_MESSAGE = signup_cap_message()

def save_users(users):
    """Atomically save accounts and retain a recoverable copy of prior data."""
    os.makedirs(os.path.dirname(USERS_FILE) or '.', exist_ok=True)
    temp_path = USERS_FILE + '.tmp'
    backup_path = USERS_FILE + '.bak'

    # Preserve the current file before replacing it, including a corrupt/empty file.
    if os.path.isfile(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as current:
                current_raw = current.read()
            if current_raw.strip():
                try:
                    json.loads(current_raw)
                    shutil.copy2(USERS_FILE, backup_path)
                except json.JSONDecodeError:
                    corrupt_path = USERS_FILE + '.corrupt-' + datetime.now().strftime('%Y%m%d-%H%M%S')
                    shutil.copy2(USERS_FILE, corrupt_path)
            else:
                corrupt_path = USERS_FILE + '.corrupt-' + datetime.now().strftime('%Y%m%d-%H%M%S')
                shutil.copy2(USERS_FILE, corrupt_path)
        except OSError:
            app.logger.exception('Could not preserve existing account database before save')
            raise

    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, USERS_FILE)
    except Exception:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
        raise

def normalized_email(value):
    return (value or '').strip().casefold()

def is_allowed_email(value):
    """Only institutional iith.ac.in email addresses may be registered or linked."""
    email = normalized_email(value)
    return bool(re.fullmatch(r"[^@\s]+@iith\.ac\.in", email))

def unique_folder_name(display_name, users, exclude_username=None):
    raw = safe_folder_name(display_name)
    if not raw:
        return None
    candidate = raw
    n = 2
    used = {str(u.get('folder','')).casefold() for key,u in users.items()
            if isinstance(u,dict) and key != exclude_username}
    while candidate.casefold() in used or os.path.exists(os.path.join(BASE_STORAGE_DIR, candidate)):
        candidate = f"{raw} ({n})"
        n += 1
    return candidate

def log_session_event(username, event, method='password'):
    """Append a login/logout record; prune records older than 10 days."""
    if not username:
        return
    path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
    now = datetime.now(timezone.utc)
    try:
        events = []
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    events = loaded
        cutoff = now - timedelta(days=10)
        kept = []
        for item in events:
            try:
                when = datetime.fromisoformat(item.get('timestamp', '').replace('Z', '+00:00'))
                if when >= cutoff:
                    kept.append(item)
            except Exception:
                continue
        kept.append({'event': event, 'method': method, 'timestamp': now.isoformat(timespec='seconds')})
        temp = path + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f:
            json.dump(kept, f, indent=2)
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    except (OSError, ValueError, TypeError):
        app.logger.exception('Could not update session activity log')

def send_email(to_address, subject, body):
    if not SMTP_USERNAME or not SMTP_PASSWORD or not MAIL_FROM:
        raise RuntimeError('Email is not configured. Set SMTP_USERNAME, SMTP_PASSWORD, and MAIL_FROM.')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = MAIL_FROM
    msg['To'] = to_address
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)

def send_welcome_email(user):
    email = user.get('email')
    if not email:
        return
    try:
        send_email(email, 'Welcome to Cyber Drive',
                   f"Welcome to Cyber Drive, {user.get('display_name', 'there')}!\n\nYour account is ready. Your default storage allowance is 1 GiB.\n\nIf you did not create this account, please contact the server administrator.")
    except Exception:
        app.logger.warning('Welcome email could not be sent; check SMTP configuration.', exc_info=True)

def establish_login(username, user, method='password'):
    folder = safe_folder_name(user.get('folder', ''))
    if not folder:
        raise ValueError('This account has no valid storage folder.')
    session.clear()
    session['authenticated'] = True
    session['username'] = username
    session['user_folder'] = folder
    session['auth_method'] = method
    session.permanent = True
    os.makedirs(user_root_path(folder), exist_ok=True)
    log_session_event(username, 'login', method)

def render_auth(page, error=None, message=None, **extra):
    return render_template_string(AUTH_TEMPLATE, page=page, error=error, message=message,
        subtitle={'login':'Sign in to access your private files.','signup':'Verify your email to create your private drive.','verify_signup':'Confirm your email address to finish signup.','forgot':'Reset your password securely using an email code.'}.get(page,''),
        google_enabled=bool(google_oauth), signup_full=user_account_limit_reached(load_users()), **extra)

# ----------------------------- Admin dashboard -----------------------------
def read_admin_config():
    # Read JSON or simple key=value / key:value credentials.
    try:
        raw = Path(ADMIN_FILE).read_text(encoding='utf-8').strip()
    except OSError:
        app.logger.error('Admin credentials file .admin_credentials.json is missing or unreadable.')
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return {
                'username': str(data.get('admin_username', data.get('username', ''))).strip(),
                'email': str(data.get('admin_email', data.get('email', ''))).strip(),
                'password': str(data.get('admin_password', data.get('password', ''))),
                'password_hash': str(data.get('admin_password_hash', data.get('password_hash', ''))),
            }
    except json.JSONDecodeError:
        pass
    values = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        sep = '=' if '=' in line else (':' if ':' in line else None)
        if sep:
            key, value = line.split(sep, 1)
            values[key.strip().lower().replace('-', '_')] = value.strip().strip('"\'')
    return {
        'username': values.get('admin_username', values.get('username', '')),
        'email': values.get('admin_email', values.get('email', '')),
        'password': values.get('admin_password', values.get('password', '')),
        'password_hash': values.get('admin_password_hash', values.get('password_hash', '')),
    }

def write_admin_password(new_password):
    cfg = read_admin_config()
    if not cfg.get('username') or not cfg.get('email'):
        raise RuntimeError('The .admin_credentials.json file must contain the fixed admin username and email.')
    # Keep the configured identity fixed; persist only a hash of the changed password.
    data = {'admin_username': cfg['username'], 'admin_email': cfg['email'],
            'admin_password_hash': generate_password_hash(new_password)}
    os.makedirs(ADMIN_DIR, mode=0o700, exist_ok=True)
    temp = ADMIN_FILE + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, ADMIN_FILE)

def admin_password_matches(cfg, supplied):
    hashed = cfg.get('password_hash', '')
    if hashed:
        try:
            return check_password_hash(hashed, supplied)
        except (ValueError, TypeError):
            return False
    saved = cfg.get('password', '')
    if not saved:
        return False
    # Also accept a Werkzeug hash accidentally stored in the password field.
    if saved.startswith(('scrypt:', 'pbkdf2:')):
        try:
            return check_password_hash(saved, supplied)
        except (ValueError, TypeError):
            return False
    return hmac.compare_digest(saved.encode('utf-8'), supplied.encode('utf-8'))

def effective_user_quota(user):
    """Return base allocation unless an admin-approved quota override exists."""
    base_bytes = current_base_storage_bytes()
    if not isinstance(user, dict) or not user.get('quota_approved_at'):
        return base_bytes
    try:
        saved = int(user.get('quota_bytes', base_bytes) or base_bytes)
    except (ValueError, TypeError):
        saved = base_bytes
    # An explicit approved override may be below the current basic allocation,
    # but never below 1 GiB or above the hard 10 GiB ceiling.
    return max(1 * 1024**3, min(MAX_USER_STORAGE_BYTES, saved))

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrapped

def load_storage_requests():
    try:
        with open(STORAGE_REQUESTS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        app.logger.exception('Could not read storage requests')
        return {}

def save_storage_requests(data):
    temp = STORAGE_REQUESTS_FILE + '.tmp'
    with open(temp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush(); os.fsync(f.fileno())
    os.replace(temp, STORAGE_REQUESTS_FILE)
    try: os.chmod(STORAGE_REQUESTS_FILE, 0o600)
    except OSError: pass

def remove_user_profile(username, users):
    user = users.get(username)
    if not isinstance(user, dict):
        return False
    folder = safe_folder_name(user.get('folder', ''))
    # Only remove the account's own validated folder, never an arbitrary path.
    if folder:
        root = user_root_path(folder)
        if os.path.isdir(root) and not os.path.islink(root):
            try:
                shutil.rmtree(root)
            except OSError:
                app.logger.exception('Could not remove storage folder for user %r', username)
                return False
    users.pop(username, None)
    requests_data = load_storage_requests()
    requests_data.pop(username, None)
    save_storage_requests(requests_data)
    return True

ADMIN_LOGIN_TEMPLATE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{{ csrf_token() }}"><link rel="icon" href="/cloud-icon.svg?v=4"><title>Cyber Drive — Admin Login</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070b13;color:#e2e8f0;font:15px system-ui}.card{width:min(420px,92vw);padding:28px;border:1px solid #263448;border-radius:18px;background:#0b1220;box-shadow:0 24px 70px #0008}h1{margin:0 0 6px;font-size:25px}p{color:#94a3b8}label{display:block;margin-top:16px}.field{position:relative}.field input{width:100%;margin-top:7px;padding:12px 44px 12px 12px;border-radius:9px;border:1px solid #334155;background:#070b13;color:#fff}.toggle{position:absolute;right:7px;top:14px;width:30px;height:30px;margin:0;padding:5px;border:0;background:transparent;color:#67e8f9;cursor:pointer}.toggle svg{width:20px;height:20px}.submit{width:100%;margin-top:20px;padding:12px;border:0;border-radius:9px;background:#00e5ff;color:#041018;font-weight:800;cursor:pointer}.error{color:#fca5a5}.back{color:#67e8f9;text-decoration:none}</style></head><body><main class="card"><h1>Cyber Drive Admin</h1><p>Restricted administrator access</p>{% if error %}<p class="error">{{ error }}</p>{% endif %}<form method="post"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><label>Admin email or username<div class="field"><input name="identity" value="{{ identity }}" autocomplete="username" required></div></label><label>Password<div class="field"><input id="adminPassword" name="password" type="password" autocomplete="current-password" required><button class="toggle" type="button" id="togglePassword" aria-label="Show password" title="Show password"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button></div></label><button class="submit" type="submit">Sign in</button></form><p><a class="back" href="/">← Back to Cyber Drive</a></p></main><script>const p=document.getElementById('adminPassword'),b=document.getElementById('togglePassword');b.addEventListener('click',()=>{const show=p.type==='password';p.type=show?'text':'password';b.setAttribute('aria-label',show?'Hide password':'Show password');b.title=show?'Hide password':'Show password';b.innerHTML=show?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3l18 18"/><path d="M2 12s3.6-7 10-7 10 7 10 7"/></svg>':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>'});</script></body></html>'''

ADMIN_DASHBOARD_TEMPLATE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="{{ csrf_token() }}"><link rel="icon" href="/cloud-icon.svg?v=4"><title>Cyber Drive — Admin Dashboard</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#070b13;color:#e2e8f0;font:14px system-ui}.wrap{max-width:1380px;margin:auto;padding:26px 18px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:22px}.eyebrow{color:#67e8f9;text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:800}h1{font-size:28px;margin:3px 0}h2{font-size:18px;margin:0 0 14px}.muted{color:#94a3b8}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:22px}.stat,.panel{background:#0b1220;border:1px solid #223044;border-radius:14px;padding:18px}.num{font-size:27px;font-weight:800}.layout{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;align-items:stretch}.layout>aside{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;align-items:stretch}.layout>.panel,.layout>aside>.panel{min-width:0;min-height:220px}.request-launcher{display:flex;flex-direction:column;align-items:flex-start;justify-content:center;gap:10px}.request-launcher .num{font-size:42px;line-height:1}.request-launcher p{margin:0}.layout>aside>.panel{margin-top:0!important}.layout>aside>.panel{margin-top:0!important;min-width:0}.search{width:100%;padding:11px;border:1px solid #334155;border-radius:9px;background:#070b13;color:#fff;margin:0 0 12px}.userrow{display:flex;align-items:center;gap:10px;padding:12px 8px;border-top:1px solid #1e293b}.userrow:first-of-type{border-top:0}.userrow input{accent-color:#00e5ff}.grow{flex:1;min-width:0}.username{font-weight:750;overflow-wrap:anywhere}.quotaInput{font:inherit;font-size:15px;font-weight:750!important;border:1px solid #155e75!important;border-radius:10px!important;background:linear-gradient(135deg,#071522,#0b1220)!important;padding:10px 12px!important;outline:none}.quotaInput:focus{border-color:#00e5ff!important;box-shadow:0 0 0 3px #00e5ff22}.quota-editor-help{color:#94a3b8;font-size:12px;line-height:1.55;margin-top:10px}.detail{margin-top:10px;padding:16px;border-radius:12px;background:linear-gradient(145deg,#0a1423,#070b13);border:1px solid #263b50;box-shadow:inset 0 1px 0 #ffffff08}.detail>div[style*="align-items:end"]{padding:12px;margin-top:12px!important;border:1px solid #263448;border-radius:10px;background:#0b1220}.detail label{font-size:12px;color:#a5b4c8;font-weight:700}.quotaInput{width:140px!important;min-height:42px}.storage-danger-actions{padding-top:10px;border-top:1px solid #263448}.storage-danger-actions .btn{font-size:12px;line-height:1.35;white-space:normal}.always-visible-delete-actions{margin-top:10px;padding-top:10px}.always-visible-delete-actions .btn{flex:1 1 150px;justify-content:center}.saveQuotaBtn{min-height:42px;box-shadow:0 5px 16px #00e5ff18}.userrow{align-items:flex-start}.userrow .viewBtn{margin-top:0}@media(max-width:620px){.always-visible-delete-actions{display:grid;grid-template-columns:1fr}.always-visible-delete-actions .btn{width:100%}}.detail .quotaInput{width:132px!important;min-height:42px}.detail .saveQuotaBtn{min-height:42px;padding:10px 16px;box-shadow:0 5px 16px #00e5ff18}.detail>div[style*="align-items:end"]{padding:12px;border:1px solid #263448;border-radius:10px;background:#0a1321}.quota-editor-help{padding:9px 11px;border:1px solid #263448;border-radius:9px;background:#0a1321}.always-visible-delete-actions{display:flex!important;visibility:visible!important;opacity:1!important;flex-wrap:wrap;gap:8px;margin-top:10px}.always-visible-delete-actions .btn{flex:1 1 150px;justify-content:center;min-height:38px}@media(max-width:620px){.detail>div[style*="align-items:end"]{align-items:stretch!important}.detail .quotaInput{width:100%!important}.detail .saveQuotaBtn{width:100%;justify-content:center}.always-visible-delete-actions{display:grid!important;grid-template-columns:1fr}.always-visible-delete-actions .btn{width:100%}}/* Refined admin quota controls and always-visible, clearly separated deletion actions. */
.userrow{background:linear-gradient(110deg,rgba(15,23,42,.55),rgba(7,11,19,.15));border-radius:12px;margin:5px 0;padding:14px 12px;transition:border-color .15s,background .15s;border:1px solid transparent}
.userrow:hover{border-color:#263b50;background:linear-gradient(110deg,rgba(8,51,68,.24),rgba(15,23,42,.55))}
.userrow .email{margin-top:4px;line-height:1.5}
.detail{margin-top:12px!important;padding:16px!important;border-radius:14px!important;background:linear-gradient(145deg,#0d1929,#080d17)!important;border:1px solid #2a4058!important}
.detail>div[style*="align-items:end"]{display:flex;gap:12px;align-items:end;flex-wrap:wrap;padding:14px!important;border:1px solid #263b50!important;border-radius:12px!important;background:#0b1422!important}
.detail label{gap:7px!important}
.detail .quotaInput{width:150px!important;min-height:44px!important;font-size:16px!important}
.detail .saveQuotaBtn{min-height:44px;padding:11px 18px!important;border-radius:10px!important}
.quota-editor-help{margin-top:10px!important;padding:10px 12px!important;border:1px solid #263448!important;border-radius:10px!important;background:#091321!important}
.storage-danger-actions{display:flex!important;visibility:visible!important;opacity:1!important;gap:8px!important;flex-wrap:wrap!important;margin-top:12px!important;padding-top:12px!important;border-top:1px solid #263448!important}
.storage-danger-actions .deleteStorageBtn{background:transparent!important;border:1px solid #b45309!important;color:#fcd34d!important}
.storage-danger-actions .deleteStorageBtn:hover{background:#78350f44!important;border-color:#f59e0b!important}
.storage-danger-actions .deleteOneBtn{background:#7f1d1d!important;border:1px solid #ef4444!important;color:#fff!important}
.storage-danger-actions .deleteOneBtn:hover{background:#991b1b!important;border-color:#f87171!important}
.storage-danger-actions .btn{flex:1 1 180px!important;min-height:42px!important;justify-content:center!important;white-space:normal!important;text-align:center!important;line-height:1.35!important;border-radius:10px!important}
.email{color:#94a3b8;font-size:12px;overflow-wrap:anywhere}.btn{border:1px solid #334155;background:#111c2d;color:#e2e8f0;padding:8px 10px;border-radius:8px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px}.btn:hover{border-color:#00e5ff}.danger{border-color:#7f1d1d;color:#fecaca}.primary{background:#00e5ff;color:#041018;border-color:#00e5ff;font-weight:800}.actions{display:flex;gap:8px;flex-wrap:wrap}.detail{margin-top:10px;padding:12px;border-radius:9px;background:#070b13;border:1px solid #263448}.hidden{display:none!important}.request{padding:14px 0;border-top:1px solid #263448}.request:first-of-type{border-top:0}.reason{white-space:pre-wrap;overflow-wrap:anywhere;background:#070b13;padding:10px;border-radius:8px;margin:9px 0}.tag{display:inline-block;border:1px solid #334155;border-radius:999px;padding:3px 8px;color:#a5f3fc;font-size:12px}.notice{padding:11px;border:1px solid #155e75;border-radius:9px;background:#083344;color:#a5f3fc;margin-bottom:14px}.error{color:#fca5a5}.formrow{margin-top:10px}.formrow label{display:block;color:#cbd5e1;margin-bottom:5px}.formrow input{width:100%;padding:10px;border-radius:8px;border:1px solid #334155;background:#070b13;color:#fff}.footer{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-top:20px}@media(max-width:1100px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}.layout>aside{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){.grid,.layout>aside{grid-template-columns:1fr}.wrap{padding:18px 12px}}</style></head><body><main class="wrap"><header class="top"><div><div class="eyebrow">Cyber Drive · Administration</div><h1>Admin dashboard</h1><div class="muted">Signed in as {{ admin_username }} · No drive storage assigned</div></div><form method="post" action="/admin/logout"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button class="btn" title="End admin session">↪ Log out</button></form></header>{% if notice %}<div class="notice cd-transient-notice" role="status">{{ notice }}</div>{% endif %}{% if error %}<div class="notice error cd-transient-notice" role="alert">{{ error }}</div>{% endif %}<section class="grid"><div class="stat"><div class="muted">Client accounts</div><div class="num">{{ users|length }} / {{ settings.max_accounts }}</div><div class="muted">Admin account excluded from the limit</div></div><div class="stat"><div class="muted">Client files stored</div><div class="num">{{ total_used_gb }} GB</div><div class="muted">Combined size of all clients’ files</div></div><div class="stat"><div class="muted">Server disk capacity</div><div class="num">{{ server_total_gb }} GB</div><div class="muted">Filesystem hosting Cyber Drive storage</div></div><div class="stat"><div class="muted">Server disk free</div><div class="num">{{ server_free_gb }} GB</div><div class="muted">Filesystem used: {{ server_used_gb }} GB</div></div></section><section class="grid" style="grid-template-columns:repeat(2,minmax(0,1fr));margin-top:-6px"><div class="stat"><div class="muted">Pending storage requests</div><div class="num">{{ requests|length }}</div><div class="muted">Each request changes quota by 1–3 GB; total allocation 1–10 GB</div></div><div class="stat"><div class="muted">Allocated client quota</div><div class="num">{{ users|sum(attribute='quota_gb') }} GB</div><div class="muted">Combined allocation across all client accounts</div></div></section><div class="layout"><section class="panel"><div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:12px"><h2 style="margin:0">User profiles</h2><a class="btn primary" href="/admin/files">🗂 Manage client files</a></div><p class="muted">Profile details are shown here. Use Manage client files to inspect and delete individual stored files.</p><input class="search" id="userSearch" placeholder="Search usernames…" aria-label="Search usernames"><form method="post" action="/admin/users/delete-selected" id="bulkForm"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><div class="actions" style="margin-bottom:10px"><label class="btn" title="Select or deselect all visible profiles"><input id="selectAll" type="checkbox" style="accent-color:#00e5ff"> Select all</label><button class="btn danger" type="submit" title="Delete selected profiles and their stored files" onclick="return confirm('Delete all selected profiles and their files? This cannot be undone.')">🗑 Delete selected</button></div><div id="userList">{% for u in users %}<div class="userrow" data-name="{{ u.username|lower }}"><input type="checkbox" name="usernames" value="{{ u.username }}" aria-label="Select {{ u.username }}"><div class="grow"><div class="username">{{ u.username }}</div><div class="email">Using {{ '%.2f'|format(u.used_gb) }} GB of {{ u.quota_gb|int }} GB</div><div class="detail hidden"><b>Username:</b> {{ u.username }}<br><b>Email:</b> {{ u.email or 'No email recorded' }}<br><b>Storage allocation:</b> {{ u.quota_gb|int }} GB<br><b>Storage used:</b> {{ '%.2f'|format(u.used_gb) }} GB<div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-top:12px" onclick="event.stopPropagation()"><label style="display:grid;gap:4px">Allocated GB<input type="number" class="quotaInput" min="1" max="10" step="1" value="{{ u.quota_gb|int }}" required style="width:120px;padding:8px;border:1px solid #334155;border-radius:7px;background:#070b13;color:#fff"></label><button class="btn primary saveQuotaBtn" type="button" data-username="{{ u.username }}">Save quota</button></div><div class="quota-editor-help">Set the total space this account may use. Changes take effect on the client dashboard automatically.</div></div><div class="actions storage-danger-actions always-visible-delete-actions" style="display:flex!important;visibility:visible!important;opacity:1!important"><button class="btn danger deleteStorageBtn" type="button" data-username="{{ u.username }}" title="Delete this client’s stored files and folders but keep their profile">🗑 Delete storage only</button><button class="btn danger deleteOneBtn" type="button" data-username="{{ u.username }}" title="Delete this profile and all its stored files">🗑 Delete storage + profile</button></div></div><button class="btn viewBtn" type="button" title="View profile details only" aria-label="View {{ u.username }} details">👁</button></div>{% else %}<p class="muted">No registered profiles yet.</p>{% endfor %}</div></form><form method="post" id="singleDelete" action="/admin/users/delete" hidden><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" id="deleteUsername"></form><form method="post" id="storageOnlyDelete" action="/admin/users/delete-storage" hidden><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" id="storageDeleteUsername"></form><form method="post" id="adminQuotaForm" action="/admin/users/storage" hidden><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" id="quotaUsername"><input type="hidden" name="quota_gb" id="quotaValue"></form></section><aside><section class="panel request-launcher"><h2>Storage change requests</h2><div class="num">{{ requests|length }}</div><p class="muted">Pending requests stay hidden until you open the request window.</p><button class="btn primary" type="button" id="openRequests">View requests ({{ requests|length }})</button></section><section class="panel" style="margin-top:16px"><h2>Account &amp; storage settings</h2><p class="muted">Changes apply to new accounts immediately. When the base storage changes, existing users on the previous base allocation are updated and all users are emailed about the policy change.</p><div class="stat" style="margin:10px 0"><div class="muted">Available cloud storage (actual cloud files only)</div><div class="num">{{ settings.cloud_available_gb }} GB</div><div class="muted">Used by Cyber Drive: {{ settings.cloud_used_gb }} GB · Effective cap: {{ settings.effective_cloud_storage_gb }} GB</div></div><form method="post" action="/admin/settings"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><div class="formrow"><label>Maximum regular client accounts</label><input type="number" name="max_accounts" min="1" max="10000" value="{{ settings.max_accounts }}" required></div><div class="formrow"><label>Basic storage per account (GB, 1–5)</label><input type="number" name="base_storage_gb" min="1" max="5" value="{{ settings.base_storage_gb }}" required></div><div class="formrow"><label>Maximum cloud storage allocation (GB)</label><input type="number" name="max_cloud_storage_gb" min="1" step="1" value="{{ settings.max_cloud_storage_gb }}" required><div class="muted">Must fit within current system free space while preserving 1 GB for the server. The effective cap automatically shrinks if free disk space drops.</div></div><button class="btn primary" style="margin-top:12px" type="submit" onclick="return confirm('Save account limits and storage policy?')">Save settings</button></form><form method="post" action="/admin/wipe-data" style="margin-top:14px"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button class="btn danger" type="submit" onclick="return confirm('PERMANENTLY DELETE ALL CLIENT FILES? Accounts will remain, but all stored files and folders will be wiped. This cannot be undone.')">🗑 Wipe all client data</button></form><p class="muted">Wiping removes client files and folders but keeps accounts and settings. Each user quota remains 1–10 GB. Lowering the account limit never deletes existing accounts; it pauses new registrations until the count is below the limit.</p></section><section class="panel" style="margin-top:16px"><h2>Administration tools</h2><p class="muted">Admin activity is limited to the last 10 days. Open the wide log window only when needed; clear it when desired.</p><button class="btn primary" type="button" id="openAdminLogs">View admin logs ({{ admin_events|length }})</button></section><section class="panel" style="margin-top:16px"><h2>Admin password</h2><p class="muted">Admin username and email are fixed. Only the password can be changed.</p><form method="post" action="/admin/change-password"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><div class="formrow"><label>Current password</label><input type="password" name="current_password" required autocomplete="current-password"></div><div class="formrow"><label>New password (at least 12 characters)</label><input type="password" name="new_password" minlength="12" required autocomplete="new-password"></div><div class="formrow"><label>Confirm new password</label><input type="password" name="confirm_password" minlength="12" required autocomplete="new-password"></div><button class="btn primary" style="margin-top:12px" type="submit">Change password</button></form></section></aside></div><dialog id="requestsDialog" class="admin-modal"><div class="modal-head"><div><h2>Storage change requests</h2><p class="muted">Review increases and decreases · pending requests only</p></div><button class="btn" type="button" id="closeRequests">✕ Close</button></div><div class="modal-content">{% for r in requests %}<article class="request"><div class="username">{{ r.username }}</div><div class="email">{{ r.email }}{% if r.created_at %} · Submitted {{ r.created_at }}{% endif %}</div><p><span class="tag">Current: {{ r.current_gb }} GB</span> <span class="tag">{{ 'Increase' if r.request_type == 'increase' else 'Decrease' }}: {{ '+' if r.request_type == 'increase' else '−' }}{{ r.additional_gb }} GB</span> <span class="tag">After approval: {{ r.requested_gb }} GB</span></p><div class="reason">{{ r.reason }}</div><div class="actions"><form method="post" action="/admin/storage-request/approve"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" value="{{ r.username }}"><button class="btn primary" type="submit">✓ Approve</button></form><form method="post" action="/admin/storage-request/reject"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" value="{{ r.username }}"><button class="btn danger" type="submit" onclick="return confirm('Reject this storage request?')">✕ Reject</button></form></div></article>{% else %}<p class="muted">No pending storage requests.</p>{% endfor %}</div></dialog>
<dialog id="adminLogsDialog" class="admin-modal"><div class="modal-head"><div><h2>Admin audit log</h2><p class="muted">Recent sign-ins and administrative actions · newest first</p></div><div class="actions"><form method="post" action="/admin/logs/clear" onsubmit="return confirm('Clear all admin audit logs? This cannot be undone.')"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><button class="btn danger" type="submit">Clear log</button></form><button class="btn" type="button" id="closeAdminLogs">✕ Close</button></div></div><div class="modal-content">{% for e in admin_events %}<article class="request"><div class="username">{{ e.action }}</div><div class="email">{{ e.time }} · Admin: {{ e.admin }} · IP: {{ e.ip or 'unknown' }}</div>{% if e.details %}<div class="reason">{{ e.details }}</div>{% endif %}</article>{% else %}<p class="muted">No admin events recorded yet.</p>{% endfor %}</div></dialog><style>.admin-modal{width:min(1120px,94vw);max-width:1120px;max-height:84vh;overflow:hidden;padding:0;border:1px solid #334155;border-radius:18px;background:#0b1220;color:#e2e8f0;box-shadow:0 24px 100px #000b}.admin-modal::backdrop{background:#020617c9;backdrop-filter:blur(5px)}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:20px 22px;border-bottom:1px solid #263448}.modal-head h2{margin:0 0 4px}.modal-head p{margin:0}.modal-content{padding:8px 22px 20px;max-height:calc(84vh - 88px);overflow:auto}.admin-modal .request{padding:14px 0}.userrow .viewBtn{flex-shrink:0}@media(max-width:620px){.modal-head{align-items:flex-start;flex-direction:column}.modal-content{padding:8px 14px 16px}}</style><div class="footer"><span class="muted">Admin actions are logged by the server; profile deletion permanently removes that user's stored folder.</span><a class="btn" href="/">Open user login</a></div></main><script>
const search=document.getElementById('userSearch');
search.addEventListener('input',()=>{const q=search.value.toLowerCase();document.querySelectorAll('.userrow').forEach(row=>row.classList.toggle('hidden',!row.dataset.name.includes(q)));});
function toggleDetails(row){const detail=row.querySelector('.detail');if(!detail)return;detail.classList.toggle('hidden');const eye=row.querySelector('.viewBtn');if(eye)eye.textContent=detail.classList.contains('hidden')?'👁':'🙈';}
document.querySelectorAll('.viewBtn').forEach(btn=>btn.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();toggleDetails(btn.closest('.userrow'));}));
document.querySelectorAll('.userrow .grow').forEach(grow=>grow.addEventListener('click',e=>{if(e.target.closest('button,input,label,a'))return;toggleDetails(grow.closest('.userrow'));}));
const logsDialog=document.getElementById('adminLogsDialog');document.getElementById('openAdminLogs').addEventListener('click',()=>logsDialog.showModal());document.getElementById('closeAdminLogs').addEventListener('click',()=>logsDialog.close());
const requestsDialog=document.getElementById('requestsDialog');document.getElementById('openRequests').addEventListener('click',()=>requestsDialog.showModal());document.getElementById('closeRequests').addEventListener('click',()=>requestsDialog.close());
const selectAll=document.getElementById('selectAll');selectAll.addEventListener('change',()=>document.querySelectorAll('#userList .userrow:not(.hidden) input[type=checkbox]').forEach(cb=>cb.checked=selectAll.checked));
function postHiddenForm(formId, fields){const form=document.getElementById(formId);if(!form){alert('The form could not be found. Please refresh the admin page.');return;}for(const [id,value] of Object.entries(fields)){const input=document.getElementById(id);if(!input){alert('A required form field is missing. Please refresh the admin page.');return;}input.value=String(value);}HTMLFormElement.prototype.submit.call(form);}
document.querySelectorAll('.deleteOneBtn').forEach(btn=>btn.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();const name=btn.dataset.username;if(!name)return alert('Could not identify this profile. Refresh the page and try again.');if(confirm('Delete profile "'+name+'" and all its stored files? This cannot be undone.'))postHiddenForm('singleDelete',{deleteUsername:name});}));
document.querySelectorAll('.deleteStorageBtn').forEach(btn=>btn.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();const name=btn.dataset.username;if(!name)return alert('Could not identify this profile. Refresh the page and try again.');if(confirm('Delete ALL files and folders for "'+name+'" but KEEP the profile and login? This cannot be undone.'))postHiddenForm('storageOnlyDelete',{storageDeleteUsername:name});}));
document.querySelectorAll('.saveQuotaBtn').forEach(btn=>btn.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();const name=btn.dataset.username;const input=btn.parentElement.querySelector('.quotaInput');const n=Number(input&&input.value);if(!name)return alert('Could not identify this profile. Refresh the page and try again.');if(!Number.isInteger(n)||n<1||n>10){alert('Quota must be a whole number from 1 to 10 GB.');if(input)input.focus();return;}if(confirm('Set '+name+' allocation to '+n+' GB?'))postHiddenForm('adminQuotaForm',{quotaUsername:name,quotaValue:n});}));
document.getElementById('bulkForm').addEventListener('submit',e=>{if(!document.querySelector('#userList input[type=checkbox]:checked')){e.preventDefault();alert('Select at least one profile first.')}});
</script><script>
(function(){const eye='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';const hide='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3l18 18"/><path d="M2 12s3.6-7 10-7 10 7 10 7"/></svg>';document.querySelectorAll('input[type="password"]').forEach(i=>{const w=document.createElement('span');w.style.cssText='display:block;position:relative;width:100%';i.parentNode.insertBefore(w,i);w.appendChild(i);i.style.paddingRight='42px';const b=document.createElement('button');b.type='button';b.innerHTML=eye;b.title='Show password';b.setAttribute('aria-label','Show password');b.style.cssText='position:absolute;right:4px;top:50%;transform:translateY(-50%);width:32px;height:32px;padding:6px;margin:0;background:transparent;border:0;color:#94a3b8;cursor:pointer';b.addEventListener('click',()=>{const show=i.type==='password';i.type=show?'text':'password';b.innerHTML=show?hide:eye;b.title=show?'Hide password':'Show password';b.setAttribute('aria-label',b.title)});w.appendChild(b)})})();
</script><script>(function(){document.querySelectorAll('.cd-transient-notice').forEach(function(el){var timer=setTimeout(function(){el.style.transition='opacity .35s ease,transform .35s ease';el.style.opacity='0';el.style.transform='translateY(-5px)';setTimeout(function(){el.remove()},400)},5000);el.addEventListener('click',function(){clearTimeout(timer);el.style.opacity='0';setTimeout(function(){el.remove()},400)});});})();</script></body></html>'''

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # Keep legacy URLs compatible, but all authentication happens at the main login page.
    return redirect(url_for('login'))

@app.route('/admin/logs/clear', methods=['POST'])
@admin_required
def clear_admin_logs():
    try:
        os.makedirs(ADMIN_DIR, mode=0o700, exist_ok=True)
        temp_path = ADMIN_AUDIT_FILE + '.tmp'
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump([], f)
            f.flush(); os.fsync(f.fileno())
        os.replace(temp_path, ADMIN_AUDIT_FILE)
        try: os.chmod(ADMIN_AUDIT_FILE, 0o600)
        except OSError: pass
        return redirect(url_for('admin_dashboard', notice='Admin audit log cleared. New actions will be recorded from now on.'))
    except OSError:
        app.logger.exception('Could not clear admin audit log')
        return redirect(url_for('admin_dashboard', error='Could not clear the admin audit log. Please try again.'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    users_db = load_users()
    users = []
    for username, user in users_db.items():
        if not isinstance(user, dict):
            continue
        folder = safe_folder_name(user.get('folder', ''))
        used = get_folder_size(user_root_path(folder)) if folder else 0
        quota = max(1, min(10, effective_user_quota(user) // 1024**3))
        users.append({'username': str(username), 'email': str(user.get('email', '')), 'quota_gb': quota,
                      'used_gb': round(used/(1024**3), 3)})
    users.sort(key=lambda item: item['username'].casefold())
    total_used_gb = round(sum(item['used_gb'] for item in users), 2)
    try:
        disk = shutil.disk_usage(BASE_STORAGE_DIR)
        server_total_gb = round(disk.total / (1024**3), 2)
        server_free_gb = round(disk.free / (1024**3), 2)
        server_used_gb = round((disk.total - disk.free) / (1024**3), 2)
    except OSError:
        server_total_gb = server_free_gb = server_used_gb = 0
    request_db = load_storage_requests()
    requests_list = []
    for username, item in request_db.items():
        user = users_db.get(username)
        if not isinstance(user, dict) or not isinstance(item, dict):
            continue
        current_gb = int(effective_user_quota(user) // (1024**3))
        try:
            additional_gb = int(item.get('additional_gb', int(item.get('requested_gb', current_gb)) - current_gb))
        except (TypeError, ValueError):
            additional_gb = 0
        request_type = item.get('request_type', 'increase')
        projected_gb = current_gb + additional_gb if request_type == 'increase' else current_gb - additional_gb
        requests_list.append({'username': username, 'email': user.get('email', ''),
            'request_type': request_type, 'current_gb': current_gb, 'additional_gb': additional_gb,
            'requested_gb': projected_gb, 'reason': item.get('reason', ''),
            'created_at': item.get('created_at', '')})
    requests_list.sort(key=lambda item: item['username'].casefold())
    settings = load_admin_settings()
    effective_limit = enforce_dynamic_cloud_limit()
    cloud_used = cloud_usage_bytes()
    settings['effective_cloud_storage_gb'] = round(effective_limit / 1024**3, 2)
    settings['cloud_available_gb'] = round(max(0, effective_limit-cloud_used) / 1024**3, 2)
    settings['cloud_used_gb'] = round(cloud_used / 1024**3, 2)
    return render_template_string(ADMIN_DASHBOARD_TEMPLATE, users=users, requests=requests_list, settings=settings,
        total_used_gb=total_used_gb, server_total_gb=server_total_gb,
        server_free_gb=server_free_gb, server_used_gb=server_used_gb,
        admin_events=load_admin_events(50), admin_username=session.get('admin_username', ''),
        notice=request.args.get('notice'), error=request.args.get('error'))

@app.route('/admin/settings', methods=['POST'])
@admin_required
def admin_update_settings():
    old_settings = load_admin_settings()
    try:
        base_storage_gb = int(request.form.get('base_storage_gb', ''))
        max_accounts = int(request.form.get('max_accounts', str(old_settings['max_accounts'])))
        max_cloud_storage_gb = int(request.form.get('max_cloud_storage_gb', str(old_settings['max_cloud_storage_gb'])))
    except (TypeError, ValueError):
        return redirect(url_for('admin_dashboard', error='Enter valid whole numbers for all settings.'))
    if not 1 <= base_storage_gb <= 5:
        return redirect(url_for('admin_dashboard', error='Basic storage must be between 1 and 5 GB.'))
    if not 1 <= max_accounts <= 10000:
        return redirect(url_for('admin_dashboard', error='Maximum accounts must be between 1 and 10000.'))
    if max_cloud_storage_gb < 1:
        return redirect(url_for('admin_dashboard', error='Maximum cloud storage must be at least 1 GB.'))
    try:
        disk_free = shutil.disk_usage(BASE_STORAGE_DIR).free
    except OSError:
        return redirect(url_for('admin_dashboard', error='Cannot verify available system storage right now.'))
    disk_free_before_cloud = disk_free + cloud_usage_bytes()
    if max_cloud_storage_gb * 1024**3 > max(0, disk_free_before_cloud - 1024**3):
        max_allowed = max(0, disk_free_before_cloud - 1024**3) / 1024**3
        return redirect(url_for('admin_dashboard', error=f'Maximum cloud storage exceeds safe available system space. Current maximum is {max_allowed:.2f} GB after reserving 1 GB for the server.'))
    users_for_policy = load_users()
    current_allocated = sum(effective_user_quota(record) for record in users_for_policy.values() if isinstance(record, dict))
    if max_cloud_storage_gb * 1024**3 < current_allocated:
        return redirect(url_for('admin_dashboard', error=f'Maximum cloud storage cannot be lower than the current combined client allocation ({current_allocated/1024**3:.2f} GB). Reduce user quotas first.'))
    old_base_bytes = old_settings['base_storage_gb'] * 1024**3
    new_base_bytes = base_storage_gb * 1024**3
    projected_allocated = 0
    for record in users_for_policy.values():
        if not isinstance(record, dict): continue
        saved_quota = int(record.get('quota_bytes', old_base_bytes) or old_base_bytes)
        if not record.get('quota_approved_at') and saved_quota <= old_base_bytes:
            saved_quota = new_base_bytes
        projected_allocated += max(1 * 1024**3, min(MAX_USER_STORAGE_BYTES, saved_quota))
    if projected_allocated > max_cloud_storage_gb * 1024**3:
        return redirect(url_for('admin_dashboard', error=f'These settings would allocate {projected_allocated/1024**3:.2f} GB across client accounts, above the proposed {max_cloud_storage_gb} GB cloud cap.'))
    new_settings = {'max_accounts': max_accounts, 'base_storage_gb': base_storage_gb, 'max_cloud_storage_gb': max_cloud_storage_gb, 'last_effective_cloud_storage_bytes': min(max_cloud_storage_gb * 1024**3, max(0, disk_free_before_cloud - 1024**3))}
    try:
        save_admin_settings(new_settings)
    except OSError:
        app.logger.exception('Could not save admin settings')
        return redirect(url_for('admin_dashboard', error='Could not save settings. Check folder permissions.'))

    record_admin_event('Updated server settings', f"max_accounts={max_accounts}, base_storage_gb={base_storage_gb}, max_cloud_storage_gb={max_cloud_storage_gb}")
    email_notice = ''
    if base_storage_gb != old_settings['base_storage_gb']:
        users = load_users()
        old_base = old_settings['base_storage_gb'] * 1024**3
        new_base = base_storage_gb * 1024**3
        # Update only users still on the prior base policy; keep explicitly approved upgrades intact.
        for user in users.values():
            if not isinstance(user, dict):
                continue
            try:
                saved_quota = int(user.get('quota_bytes', old_base) or old_base)
            except (TypeError, ValueError):
                saved_quota = old_base
            if not user.get('quota_approved_at') and saved_quota <= old_base:
                user['quota_bytes'] = new_base
        save_users(users)
        sent = 0
        failed = 0
        for username, user in users.items():
            if not isinstance(user, dict) or not user.get('email'):
                continue
            try:
                send_email(user['email'], 'Cyber Drive storage policy updated',
                    f"Hello {user.get('display_name') or username},\n\n"
                    f"Cyber Drive's basic storage allocation has been updated to {base_storage_gb} GB per account. "
                    "Your account's basic allocation has been adjusted if it was still using the previous default. "
                    "Any separately approved storage allocation is preserved, subject to the 10 GB maximum.\n\n"
                    "Thank you for using Cyber Drive.")
                sent += 1
            except Exception:
                failed += 1
                app.logger.warning('Could not email storage policy update to user %r', username, exc_info=True)
        email_notice = f' Storage-change email sent to {sent} user(s); {failed} email(s) could not be sent.'
    app.logger.info('Admin updated policy settings: max_accounts=%d base_storage_gb=%d', max_accounts, base_storage_gb)
    record_admin_event('Updated account/storage policy', f'max_accounts={max_accounts}; base_storage_gb={base_storage_gb}')
    return redirect(url_for('admin_dashboard', notice='Settings saved successfully.' + email_notice))


@app.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    record_admin_event('Admin logout', 'Admin signed out')
    session.clear()
    response = app.make_response(render_template_string(LOGOUT_TEMPLATE))
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    app.logger.info('ADMIN LOGOUT COMPLETE | next=goodbye_page')
    return response

@app.route('/admin/users/delete-storage', methods=['POST'])
@admin_required
def admin_delete_user_storage():
    """Delete only a client's stored files/folders; retain the account profile and quota."""
    username = request.form.get('username', '').strip()
    users = load_users()
    user = users.get(username)
    if not isinstance(user, dict):
        return redirect(url_for('admin_dashboard', error='That client profile no longer exists.'))
    folder = safe_folder_name(user.get('folder', ''))
    if not folder:
        return redirect(url_for('admin_dashboard', error='This profile has no valid storage folder.'))
    root = user_root_path(folder)
    try:
        if os.path.islink(root):
            return redirect(url_for('admin_dashboard', error='Storage folder is a symbolic link; refusing to delete it.'))
        if os.path.isdir(root):
            # Remove files without following symlinks; retain the account root folder.
            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                safe_dirs = []
                for dirname in dirs:
                    target_dir = os.path.join(current, dirname)
                    if os.path.islink(target_dir):
                        os.unlink(target_dir)  # remove the link itself; never follow it
                    else:
                        safe_dirs.append(dirname)
                dirs[:] = safe_dirs
                for filename in files:
                    target = os.path.join(current, filename)
                    if os.path.islink(target) or os.path.isfile(target):
                        os.unlink(target)
            for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
                for dirname in dirs:
                    target = os.path.join(current, dirname)
                    if not os.path.islink(target) and os.path.isdir(target):
                        os.rmdir(target)
        record_admin_event('Deleted client storage only', f'account={username}; profile retained')
        record_user_activity(username, 'storage_deleted', 'An administrator deleted all files and folders in your Cyber Drive storage. Your account profile remains active.')
        app.logger.warning('CLIENT STORAGE PURGED | account=%s | profile=retained', username)
        return redirect(url_for('admin_dashboard', notice=f'Deleted all stored files for {username}. The profile and account remain.'))
    except OSError:
        app.logger.exception('Could not delete storage only for client %r', username)
        return redirect(url_for('admin_dashboard', error=f'Could not completely clear {username} storage. Check the terminal log.'))


@app.route('/admin/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    username = request.form.get('username', '')
    users = load_users()
    if username not in users:
        return redirect(url_for('admin_dashboard', error='That profile no longer exists.'))
    if remove_user_profile(username, users):
        save_users(users)
        app.logger.warning('Admin deleted user profile %r', username)
        record_admin_event('Deleted user profile', username)
        return redirect(url_for('admin_dashboard', notice=f'Profile {username} and its stored files were deleted.'))
    return redirect(url_for('admin_dashboard', error='Could not delete that profile.'))

@app.route('/admin/users/delete-selected', methods=['POST'])
@admin_required
def admin_delete_selected_users():
    selected = list(dict.fromkeys(request.form.getlist('usernames')))
    users = load_users()
    deleted = []
    for username in selected:
        if username in users and remove_user_profile(username, users):
            deleted.append(username)
    if deleted:
        save_users(users)
        app.logger.warning('Admin bulk-deleted %d user profiles', len(deleted))
        record_admin_event('Bulk-deleted user profiles', ', '.join(deleted))
    return redirect(url_for('admin_dashboard', notice=f'Deleted {len(deleted)} profile(s) and their stored files.'))

@app.route('/storage/request', methods=['POST'])
@login_required
def request_storage_expansion():
    username = session['username']
    users = load_users()
    user = users.get(username, {})
    if not isinstance(user, dict):
        return redirect(url_for('login'))
    requests_db = load_storage_requests()
    if username in requests_db:
        flash('You already have a pending storage change request.')
        return redirect(url_for('browse_files'))
    reason = request.form.get('reason', '').strip()
    request_type = request.form.get('request_type', 'increase').strip().lower()
    try:
        amount_gb = int(request.form.get('additional_gb', '0'))
    except (TypeError, ValueError):
        amount_gb = 0
    current_gb = int(effective_user_quota(user) // (1024**3))
    user_folder = safe_folder_name(user.get('folder', ''))
    used_gb = get_folder_size(user_root_path(user_folder)) / (1024**3) if user_folder else 0
    if len(reason) < 10 or len(reason) > 1000:
        flash('Please provide a reason between 10 and 1000 characters.')
    elif request_type not in {'increase', 'decrease'}:
        flash('Choose whether to increase or decrease your storage.')
    elif not 1 <= amount_gb <= 3:
        flash('Each request must change storage by between 1 GB and 3 GB.')
    else:
        projected_gb = current_gb + amount_gb if request_type == 'increase' else current_gb - amount_gb
        if request_type == 'increase' and projected_gb > 10:
            flash('This request was not sent: Cyber Drive currently serves a maximum of 10 GB per user. Choose a smaller increase.')
        elif request_type == 'decrease' and projected_gb < 1:
            flash('This request cannot be sent: the minimum account allocation is 1 GB.')
        elif request_type == 'decrease' and projected_gb + 1e-9 < used_gb:
            flash(f'This request cannot be sent because you are already using {used_gb:.2f} GB. Free some space first.')
        else:
            requests_db[username] = {
                'request_type': request_type,
                'additional_gb': amount_gb,
                'current_gb': current_gb,
                'requested_gb': projected_gb,
                'reason': reason,
                'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds')
            }
            save_storage_requests(requests_db)
            action = 'increase' if request_type == 'increase' else 'decrease'
            flash(f'Your request to {action} storage by {amount_gb} GB (new total: {projected_gb} GB) has been submitted to the admin.')
    return redirect(url_for('browse_files'))

@app.route('/admin/storage-request/approve', methods=['POST'])
@admin_required
def admin_approve_storage_request():
    username = request.form.get('username', '')
    users = load_users(); requests_db = load_storage_requests()
    user = users.get(username); item = requests_db.get(username)
    if not isinstance(user, dict) or not isinstance(item, dict):
        return redirect(url_for('admin_dashboard', error='This request is no longer pending.'))
    current_gb = int(effective_user_quota(user) // (1024**3))
    request_type = item.get('request_type', 'increase')
    try:
        amount_gb = int(item.get('additional_gb', 0))
    except (TypeError, ValueError):
        return redirect(url_for('admin_dashboard', error='Invalid storage request; it was not approved.'))
    requested_gb = current_gb + amount_gb if request_type == 'increase' else current_gb - amount_gb
    folder = safe_folder_name(user.get('folder', ''))
    used_gb = get_folder_size(user_root_path(folder)) / (1024**3) if folder else 0
    valid = 1 <= amount_gb <= 3 and 1 <= requested_gb <= 10
    if request_type == 'decrease' and requested_gb + 1e-9 < used_gb:
        valid = False
    if request_type not in {'increase', 'decrease'} or not valid:
        return redirect(url_for('admin_dashboard', error='Cannot approve this request: it violates the 1–10 GB account limit or would reduce quota below current file usage. The request remains pending.'))
    allocated_before = sum(effective_user_quota(record) for record in users.values() if isinstance(record, dict))
    projected_allocated = allocated_before - current_gb * 1024**3 + requested_gb * 1024**3
    cloud_cap = enforce_dynamic_cloud_limit()
    if projected_allocated > cloud_cap:
        return redirect(url_for('admin_dashboard', error=f'Cannot approve: total allocated quotas would exceed the current effective cloud allocation cap of {cloud_cap/1024**3:.2f} GB. The request remains pending.'))
    user['quota_bytes'] = requested_gb * 1024**3
    user['quota_approved_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    save_users(users)
    requests_db.pop(username, None); save_storage_requests(requests_db)
    action = 'increased' if request_type == 'increase' else 'decreased'
    record_admin_event('Approved storage change request', f'{username}: {action} by {amount_gb} GB; new total {requested_gb} GB')
    record_user_activity(username, 'storage_allocation', f'Your storage request was approved. Allocation {action} by {amount_gb} GB; new total {requested_gb} GB.')
    app.logger.info('STORAGE REQUEST APPROVED | account=%s | change=%s%sgb | new_quota=%s GB', username, '+' if action == 'increased' else '-', amount_gb, requested_gb)
    return redirect(url_for('admin_dashboard', notice=f'Approved {username}: storage {action} by {amount_gb} GB (new total {requested_gb} GB).'))

@app.route('/admin/users/storage', methods=['POST'])
@admin_required
def admin_adjust_user_storage():
    username = request.form.get('username', '').strip()
    try:
        new_gb = int(request.form.get('quota_gb', ''))
    except (TypeError, ValueError):
        return redirect(url_for('admin_dashboard', error='Enter a valid whole-number quota.'))
    users = load_users()
    user = users.get(username)
    if not isinstance(user, dict):
        return redirect(url_for('admin_dashboard', error='That client profile no longer exists.'))
    if not 1 <= new_gb <= 10:
        return redirect(url_for('admin_dashboard', error='Client quota must be between 1 and 10 GB.'))
    folder = safe_folder_name(user.get('folder', ''))
    used_gb = get_folder_size(user_root_path(folder)) / (1024**3) if folder else 0
    if new_gb + 1e-9 < used_gb:
        return redirect(url_for('admin_dashboard', error=f"Quota cannot be set below the client's current usage ({used_gb:.2f} GB)."))
    old_gb = int(effective_user_quota(user) // (1024**3))
    allocated_before = sum(effective_user_quota(record) for record in users.values() if isinstance(record, dict))
    projected_allocated = allocated_before - old_gb * 1024**3 + new_gb * 1024**3
    cloud_cap = enforce_dynamic_cloud_limit()
    if projected_allocated > cloud_cap:
        return redirect(url_for('admin_dashboard', error=f'This quota change would allocate {projected_allocated/1024**3:.2f} GB, exceeding the current effective cloud allocation cap of {cloud_cap/1024**3:.2f} GB.'))
    user['quota_bytes'] = new_gb * 1024**3
    user['quota_approved_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    save_users(users)
    record_admin_event('Admin changed client quota', f'{username}: {old_gb} GB -> {new_gb} GB')
    record_user_activity(username, 'storage_allocation', f'The admin changed your allocation from {old_gb} GB to {new_gb} GB. Your new limit is active now.')
    app.logger.info('CLIENT QUOTA UPDATED | account=%s | old=%s GB | new=%s GB', username, old_gb, new_gb)
    return redirect(url_for('admin_dashboard', notice=f"Updated {username}'s allocation from {old_gb} GB to {new_gb} GB."))

@app.route('/admin/storage-request/reject', methods=['POST'])
@admin_required
def admin_reject_storage_request():
    username = request.form.get('username', '')
    requests_db = load_storage_requests()
    if username not in requests_db:
        return redirect(url_for('admin_dashboard', error='This request is no longer pending.'))
    requests_db.pop(username, None); save_storage_requests(requests_db)
    app.logger.info('STORAGE REQUEST REJECTED | account=%s', username)
    record_user_activity(username, 'storage_request', 'Your storage change request was reviewed and rejected by the admin.')
    record_admin_event('Rejected storage request', username)
    return redirect(url_for('admin_dashboard', notice=f'Rejected the storage request from {username}.'))

@app.route('/admin/change-password', methods=['POST'])
@admin_required
def admin_change_password():
    cfg = read_admin_config()
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    if not admin_password_matches(cfg, current):
        return redirect(url_for('admin_dashboard', error='Current password is incorrect.'))
    if len(new) < 12:
        return redirect(url_for('admin_dashboard', error='New password must be at least 12 characters.'))
    if new != confirm:
        return redirect(url_for('admin_dashboard', error='New passwords do not match.'))
    try:
        write_admin_password(new)
    except Exception:
        app.logger.exception('Could not update admin password')
        return redirect(url_for('admin_dashboard', error='Could not save the new password to .admin_credentials.json.'))
    session['admin_username'] = cfg['username']
    record_admin_event('Changed admin password', 'Password updated successfully')
    return redirect(url_for('admin_dashboard', notice='Admin password changed successfully.'))

@app.route('/', methods=['GET', 'POST'])
def login():
    # Clear stale sessions when the account database is empty or the account was
    # removed. The login page must be shown until a real account is authenticated.
    if session.get('authenticated'):
        username_in_session = session.get('username')
        users_now = load_users()
        current_account = users_now.get(username_in_session) if isinstance(users_now, dict) else None
        if isinstance(current_account, dict) and safe_folder_name(current_account.get('folder', '')):
            return redirect(url_for('browse_files'))
        session.clear()
    error = None
    identity = ''
    if request.method == 'POST':
        identity = request.form.get('identity', '').strip()
        password = request.form.get('password', '')
        # Admin and regular accounts use one login screen. Admin credentials are
        # checked first, and a successful admin login opens the dashboard.
        admin_cfg = read_admin_config()
        admin_identity = identity.casefold() in {
            str(admin_cfg.get('username', '')).casefold(),
            str(admin_cfg.get('email', '')).casefold(),
        } and bool(identity)
        admin_password_ok = admin_password_matches(admin_cfg, password) if admin_identity else False
        if admin_identity and admin_password_ok:
            session.clear()
            session['admin_authenticated'] = True
            session['admin_username'] = admin_cfg['username']
            session.permanent = True
            app.logger.info('Admin login succeeded for configured admin account.')
            record_admin_event('Admin login succeeded', 'Successful sign-in through the shared login page')
            return redirect(url_for('admin_dashboard'))
        if admin_identity:
            # Diagnostic only: never log the submitted password or stored hash.
            record_admin_event('Admin login failed', 'Password verification failed for configured admin identity')
            app.logger.warning(
                'Admin login rejected: identity matched but password verification failed; credential file=%s',
                ADMIN_FILE,
            )
        elif identity:
            app.logger.info('Login identity did not match configured admin username/email.')
        users = load_users()
        identity_key = identity.casefold()
        username = next((key for key, value in users.items()
                         if isinstance(value, dict) and
                         (str(key).casefold() == identity_key
                          or str(value.get('folder', '')).casefold() == identity_key
                          or normalized_email(value.get('email')) == normalized_email(identity))), None)
        user = users.get(username) if username else None
        valid = False
        if isinstance(user, dict) and isinstance(user.get('password'), str):
            stored = user['password']
            if stored.startswith(('scrypt:', 'pbkdf2:')):
                try:
                    valid = check_password_hash(stored, password)
                except (ValueError, TypeError):
                    valid = False
            else:
                valid = hmac.compare_digest(stored, password)
                if valid:
                    user['password'] = generate_password_hash(password)
                    save_users(users)
        if valid and user:
            try:
                establish_login(username, user, 'password')
            except ValueError as exc:
                return render_auth('login', error=str(exc), identity=identity), 400
            return redirect(url_for('browse_files'))
        error = 'Invalid email/username or password.'
    return render_auth('login', error=error, identity=identity)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    pending = session.get('pending_signup')
    now = time.time()
    if request.method == 'GET':
        if request.args.get('restart') == '1':
            session.pop('pending_signup', None)
            pending = None
        if isinstance(pending, dict):
            if now <= float(pending.get('expires', 0)):
                refreshed = request.args.get('csrf_refresh') == '1'
                return render_auth('verify_signup', email=pending.get('email', ''),
                    message=('The resend form was refreshed for security. Please click Resend code again.' if refreshed else 'Continue with the code already sent to your email.'),
                    otp_expires_at=pending.get('expires', 0), otp_resend_at=pending.get('resend_at', 0))
            session.pop('pending_signup', None)
        return render_auth('signup')

    display_name = request.form.get('display_name', '').strip()
    email = normalized_email(request.form.get('email'))
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')
    if not display_name or not safe_folder_name(display_name) or len(display_name) > 60:
        return render_auth('signup', error='Enter a valid name without slashes or path characters.', display_name=display_name, email=email), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return render_auth('signup', error='Enter a valid email address.', display_name=display_name, email=email), 400
    if not is_allowed_email(email):
        return render_auth('signup', error='Only an @iith.ac.in institutional email address is allowed.', display_name=display_name, email=email), 400
    users = load_users()
    if user_account_limit_reached(users):
        return render_auth('signup', error=signup_cap_message(), display_name=display_name, email=email), 503
    allocated = sum(effective_user_quota(record) for record in users.values() if isinstance(record, dict))
    if allocated + current_base_storage_bytes() > enforce_dynamic_cloud_limit():
        return render_auth('signup', error='Cyber Drive has reached its total cloud-storage allocation limit. Please contact the administrator.', display_name=display_name, email=email), 503
    if any(isinstance(u, dict) and normalized_email(u.get('email')) == email for u in users.values()):
        return render_auth('signup', error='An account already uses that email. Try logging in.', display_name=display_name, email=email), 409
    requested_folder = safe_folder_name(display_name)
    requested_name_key = requested_folder.casefold() if requested_folder else ''
    name_taken = any(
        str(key).casefold() == requested_name_key
        or (isinstance(user, dict) and (
            str(user.get('folder', '')).casefold() == requested_name_key
            or str(user.get('display_name', '')).strip().casefold() == display_name.casefold()
        ))
        for key, user in users.items()
    )
    if name_taken or (requested_folder and os.path.exists(os.path.join(BASE_STORAGE_DIR, requested_folder))):
        return render_auth('signup', error='That username/home-folder name is already taken. Please choose a different name.', display_name=display_name, email=email), 409
    if len(password) < 10:
        return render_auth('signup', error='Use a password with at least 10 characters.', display_name=display_name, email=email), 400
    if password != confirm:
        return render_auth('signup', error='The passwords do not match.', display_name=display_name, email=email), 400

    # If an OTP is already pending, keep the user on the OTP screen instead of discarding it.
    if isinstance(pending, dict) and now <= float(pending.get('expires', 0)):
        return render_auth('verify_signup', email=email,
            message='A code is already pending. Enter it below or resend when the timer reaches zero.',
            otp_expires_at=pending.get('expires', 0), otp_resend_at=pending.get('resend_at', 0))

    otp = f"{secrets.randbelow(1000000):06d}"
    created = time.time()
    pending = {
        'display_name': display_name, 'email': email,
        'password_hash': generate_password_hash(password),
        'otp_hash': generate_password_hash(otp),
        'expires': created + SIGNUP_OTP_TTL_SECONDS,
        'resend_at': created + SIGNUP_OTP_RESEND_SECONDS,
        'attempts': 0,
    }
    try:
        send_email(email, 'Verify your Cyber Drive email',
                   f"Your Cyber Drive verification code is {otp}. It expires in 2 minutes. If you did not request this, ignore this email.")
    except Exception:
        app.logger.warning('Signup verification email could not be sent.', exc_info=True)
        return render_auth('signup', error='Could not send the verification email. Check SMTP settings and try again.', display_name=display_name, email=email), 503
    session['pending_signup'] = pending
    return render_auth('verify_signup', email=email, message='A verification code has been sent to your email.',
        otp_expires_at=pending['expires'], otp_resend_at=pending['resend_at'])

@app.route('/resend-signup-otp', methods=['POST'])
def resend_signup_otp():
    pending = session.get('pending_signup')
    now = time.time()
    if not isinstance(pending, dict) or now > float(pending.get('expires', 0)):
        session.pop('pending_signup', None)
        return render_auth('signup', error='The code expired. Please enter your details again.')
    if now < float(pending.get('resend_at', 0)):
        return render_auth('verify_signup', email=pending.get('email', ''),
            error='Please wait for the resend timer to reach zero.',
            otp_expires_at=pending.get('expires', 0), otp_resend_at=pending.get('resend_at', 0)), 429
    otp = f"{secrets.randbelow(1000000):06d}"
    created = time.time()
    try:
        send_email(pending['email'], 'Your new Cyber Drive verification code',
                   f"Your NEW Cyber Drive verification code is {otp}. It replaces the previous code and expires in 2 minutes. If you did not request this, ignore this email.")
    except Exception:
        app.logger.warning('Signup verification email could not be resent.', exc_info=True)
        # Keep the old pending code unchanged if sending the replacement failed.
        return render_auth('verify_signup', email=pending.get('email', ''), error='Could not resend the code. Check email configuration and try again.',
            otp_expires_at=pending.get('expires', 0), otp_resend_at=pending.get('resend_at', 0)), 503
    pending['otp_hash'] = generate_password_hash(otp)
    pending['expires'] = created + SIGNUP_OTP_TTL_SECONDS
    pending['resend_at'] = created + SIGNUP_OTP_RESEND_SECONDS
    pending['attempts'] = 0
    session['pending_signup'] = pending
    return render_auth('verify_signup', email=pending.get('email', ''), message='A new code was sent. The previous code is no longer valid.',
        otp_expires_at=pending['expires'], otp_resend_at=pending['resend_at'])

@app.route('/verify-signup', methods=['POST'])
def verify_signup():
    pending = session.get('pending_signup')
    otp = request.form.get('otp', '').strip()
    if not isinstance(pending, dict) or time.time() > float(pending.get('expires', 0)):
        session.pop('pending_signup', None)
        return render_auth('signup', error='Verification expired. Please sign up again.')
    attempts = int(pending.get('attempts', 0))
    if attempts >= 5:
        session.pop('pending_signup', None)
        return render_auth('signup', error='Too many incorrect codes. Please start signup again.'), 429
    if not re.fullmatch(r'[0-9]{6}', otp) or not check_password_hash(pending['otp_hash'], otp):
        pending['attempts'] = attempts + 1
        session['pending_signup'] = pending
        return render_auth('verify_signup', email=pending.get('email', ''), error='Incorrect verification code.', otp_expires_at=pending.get('expires', 0), otp_resend_at=pending.get('resend_at', 0)), 400
    display_name = pending['display_name']
    email = pending['email']
    users = load_users()
    if user_account_limit_reached(users):
        session.pop('pending_signup', None)
        return render_auth('signup', error=signup_cap_message()), 503
    allocated = sum(effective_user_quota(record) for record in users.values() if isinstance(record, dict))
    if allocated + current_base_storage_bytes() > enforce_dynamic_cloud_limit():
        session.pop('pending_signup', None)
        return render_auth('signup', error='Cyber Drive has reached its total cloud-storage allocation limit. Please contact the administrator.'), 503
    if any(isinstance(u, dict) and normalized_email(u.get('email')) == normalized_email(email) for u in users.values()):
        session.pop('pending_signup', None)
        return render_auth('signup', error='This email is already registered. Please log in instead.', email=email), 409
    requested_folder = safe_folder_name(display_name)
    requested_name_key = requested_folder.casefold() if requested_folder else ''
    name_taken = any(
        str(key).casefold() == requested_name_key
        or (isinstance(user, dict) and (
            str(user.get('folder', '')).casefold() == requested_name_key
            or str(user.get('display_name', '')).strip().casefold() == display_name.casefold()
        ))
        for key, user in users.items()
    )
    if not requested_folder or name_taken or os.path.exists(os.path.join(BASE_STORAGE_DIR, requested_folder)):
        session.pop('pending_signup', None)
        return render_auth('signup', error='That username/home-folder name is already taken. Please choose a different name.', display_name=display_name, email=email), 409
    # Use the exact requested home-folder name as the login username; never silently rename duplicates.
    folder = requested_folder
    username = folder
    user = {'display_name': display_name, 'email': email, 'password': pending['password_hash'],
            'folder': folder, 'provider': 'email', 'google_sub': None, 'quota_bytes': current_base_storage_bytes(),
            'email_verified': True, 'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}
    users[username] = user
    save_users(users)
    os.makedirs(user_root_path(folder), exist_ok=True)
    session.pop('pending_signup', None)
    session.pop('signup_otp_last_sent', None)
    send_welcome_email(user)
    establish_login(username, user, 'password')
    return redirect(url_for('browse_files'))

LOGOUT_TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Goodbye · Cyber Drive</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 50% 20%,#14243c 0,#080d17 48%,#05070c 100%);color:#e2e8f0;font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(560px,100%);padding:clamp(26px,6vw,48px);text-align:center;background:#0b1220eF;border:1px solid #24364d;border-radius:24px;box-shadow:0 28px 90px #0008;animation:appear .45s ease-out}.mark{width:76px;height:76px;margin:0 auto 20px;display:grid;place-items:center;border-radius:23px;border:1px solid #155e75;background:#083344;color:#67e8f9;font-size:35px;box-shadow:0 0 35px #06b6d422}h1{font-size:clamp(28px,5vw,38px);line-height:1.15;margin:0 0 12px;letter-spacing:-.04em}h1 span{color:#67e8f9}.sub{color:#94a3b8;margin:0 auto 26px;max-width:390px}.line{height:1px;background:linear-gradient(90deg,transparent,#334155,transparent);margin:26px 0}.next{display:inline-flex;justify-content:center;align-items:center;gap:10px;min-height:46px;padding:12px 20px;border-radius:11px;background:linear-gradient(120deg,#67e8f9,#60a5fa);color:#06111c;text-decoration:none;font-weight:800;box-shadow:0 8px 26px #06b6d422;transition:transform .2s,filter .2s}.next:hover{transform:translateY(-2px);filter:brightness(1.08)}.tiny{color:#64748b;font-size:12px;margin:18px 0 0}@keyframes appear{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}@media(prefers-reduced-motion:reduce){.card{animation:none}.next{transition:none}}
</style></head><body><main class="card"><div class="mark" aria-hidden="true">✓</div><h1>Bye-bye, <span>have a great time!</span></h1><p class="sub">You have been signed out of Cyber Drive. Your files are staying right where they belong, safely in your drive.</p><div class="line"></div><p class="tiny" id="redirectCountdown" aria-live="polite">Redirecting to sign in in 5...</p><a class="next" href="/">Continue to sign in now <span aria-hidden="true">→</span></a><p class="tiny">For your security, sign in again when you are ready.</p><script>(function(){var el=document.getElementById("redirectCountdown"),remaining=5;el.textContent="Redirecting to sign in in "+remaining+"...";var timer=window.setInterval(function(){remaining-=1;if(remaining<=0){window.clearInterval(timer);el.textContent="Taking you to sign in...";window.location.replace("/");return;}el.textContent="Redirecting to sign in in "+remaining+"...";},1000);})();</script></main></body></html>'''

@app.route('/logout')
def logout():
    username = session.get('username')
    method = session.get('auth_method', 'password')
    if username:
        log_session_event(username, 'logout', method)
    session.clear()
    response = app.make_response(render_template_string(LOGOUT_TEMPLATE))
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    app.logger.info('CLIENT LOGOUT COMPLETE | account=%s | next=goodbye_page', username or 'unknown')
    return response

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = normalized_email(request.form.get('email'))
        users = load_users()
        username = next((key for key, user in users.items() if isinstance(user,dict) and normalized_email(user.get('email')) == email), None)
        # Avoid exposing whether an email is registered. For a known account, send a short-lived code.
        if not email or not is_allowed_email(email):
            return render_auth('forgot', error='Wrong email entered. Use the @iith.ac.in email linked to your account.')
        if not username:
            return render_auth('forgot', error='Wrong email entered. No account was found for that email.')
        if username:
            last = session.get('otp_last_sent', 0)
            if time.time() - float(last) < RESET_OTP_COOLDOWN_SECONDS:
                return render_auth('forgot', error='Please wait before requesting another code.', otp_sent=True)
            otp = f"{secrets.randbelow(1000000):06d}"
            session['reset_otp_hash'] = generate_password_hash(otp)
            session['reset_otp_user'] = username
            session['reset_otp_expiry'] = time.time() + RESET_OTP_TTL_SECONDS
            session['otp_last_sent'] = time.time()
            try:
                send_email(email, 'Cyber Drive password reset code',
                           f"Your Cyber Drive password reset code is {otp}. It expires in 2 minutes. If you did not request this, ignore this email.")
            except Exception:
                app.logger.warning('Password reset email could not be sent.', exc_info=True)
                return render_auth('forgot', error='Email delivery is not configured or failed. Check SMTP settings.')
        return render_auth('forgot', message='If that email belongs to an account, a code has been sent.', otp_sent=bool(username))
    return render_auth('forgot', otp_sent=False)

@app.route('/reset-password', methods=['POST'])
def reset_password():
    otp = request.form.get('otp', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')
    otp_hash = session.get('reset_otp_hash')
    username = session.get('reset_otp_user')
    expiry = session.get('reset_otp_expiry', 0)
    if not otp_hash or not username or time.time() > float(expiry):
        return render_auth('forgot', error='That code has expired. Request a new one.')
    if len(password) < 10 or password != confirm:
        return render_auth('forgot', error='Passwords must match and contain at least 10 characters.', otp_sent=True)
    if not check_password_hash(otp_hash, otp):
        return render_auth('forgot', error='Invalid code. Request a new one if needed.', otp_sent=True)
    users = load_users()
    user = users.get(username)
    if not isinstance(user, dict):
        return render_auth('forgot', error='Account was not found.')
    user['password'] = generate_password_hash(password)
    user['provider'] = 'both' if user.get('google_sub') else 'email'
    save_users(users)
    for key in ('reset_otp_hash','reset_otp_user','reset_otp_expiry','otp_last_sent'):
        session.pop(key, None)
    return render_auth('login', message='Password reset successfully. You can now log in.')

@app.route('/auth/google')
def google_login():
    if not google_oauth:
        return render_auth('login', error='Google sign-in is not configured yet.'), 503
    session['google_flow'] = 'login'
    return google_oauth.authorize_redirect(GOOGLE_OAUTH_BASE_URL + url_for('google_callback'))

@app.route('/auth/google/link')
@login_required
def google_link():
    if not google_oauth:
        return redirect(url_for('browse_files'))
    session['google_flow'] = 'link'
    return google_oauth.authorize_redirect(GOOGLE_OAUTH_BASE_URL + url_for('google_callback'), prompt='select_account')

@app.route('/auth/google/callback')
def google_callback():
    if not google_oauth:
        return redirect(url_for('login'))
    try:
        token = google_oauth.authorize_access_token()
        info = token.get('userinfo') or google_oauth.userinfo()
        email = normalized_email(info.get('email'))
        sub = info.get('sub')
        if not email or not info.get('email_verified') or not sub:
            return render_auth('login', error='Google did not provide a verified email.'), 400
        if not is_allowed_email(email):
            return render_auth('login', error='Only a verified @iith.ac.in email address is allowed.'), 403
        users = load_users()
        flow = session.pop('google_flow', 'login')
        if flow == 'link' and session.get('authenticated'):
            username = session['username']
            user = users.get(username)
            if not isinstance(user, dict):
                return redirect(url_for('login'))
            owner = next((k for k,v in users.items() if isinstance(v,dict) and v.get('google_sub') == sub and k != username), None)
            if owner:
                return redirect(url_for('browse_files'))
            user['google_sub'] = sub
            user['google_email'] = email
            user['provider'] = 'both' if user.get('password') else 'google'
            # Only set the profile email if currently blank; don't silently replace verified contact email.
            if not user.get('email'):
                user['email'] = email
            save_users(users)
            return redirect(url_for('browse_files'))
        username = next((k for k,v in users.items() if isinstance(v,dict) and v.get('google_sub') == sub), None)
        if not username:
            # Enforce the same five-profile cap for Google-created accounts.
            if user_account_limit_reached(users):
                return render_auth('login', error=signup_cap_message()), 503
            allocated = sum(effective_user_quota(record) for record in users.values() if isinstance(record, dict))
            if allocated + current_base_storage_bytes() > enforce_dynamic_cloud_limit():
                return render_auth('login', error='Cyber Drive has reached its total cloud-storage allocation limit. Please contact the administrator.'), 503
            # If an email account exists, require an authenticated link rather than silently merging accounts.
            email_owner = next((k for k,v in users.items() if isinstance(v,dict) and normalized_email(v.get('email')) == email), None)
            if email_owner:
                return render_auth('login', error='An account already uses this email. Log in first, then use Account menu → Link / change Google account.'), 409
            display_name = (info.get('name') or email.split('@')[0]).strip()[:60]
            folder = unique_folder_name(display_name, users)
            username = 'u_' + secrets.token_hex(8)
            user = {'display_name': display_name, 'email': email, 'google_email': email, 'password': None,
                    'folder': folder, 'provider': 'google', 'google_sub': sub, 'quota_bytes': current_base_storage_bytes(),
                    'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}
            users[username] = user
            save_users(users)
            os.makedirs(user_root_path(folder), exist_ok=True)
            send_welcome_email(user)
        else:
            user = users[username]
        establish_login(username, user, 'google')
        return redirect(url_for('browse_files'))
    except Exception:
        app.logger.exception('Google authentication failed')
        return render_auth('login', error='Google sign-in failed. Check OAuth configuration and redirect URI.'), 400

@app.route('/account/profile', methods=['POST'])
@login_required
def update_profile():
    users = load_users()
    username = session['username']
    user = users.get(username)
    if not isinstance(user, dict):
        abort(404)
    display_name = request.form.get('display_name', '').strip()
    if not display_name or not safe_folder_name(display_name) or len(display_name) > 60:
        flash('Invalid display name.')
        return redirect(url_for('browse_files'))
    old_folder = safe_folder_name(user.get('folder', ''))
    new_folder = unique_folder_name(display_name, users, exclude_username=username)
    if old_folder and (old_folder.casefold() == display_name.casefold() or user.get('display_name', username) == display_name):
        new_folder = old_folder
    if not new_folder:
        flash('Invalid folder name.')
        return redirect(url_for('browse_files'))
    if old_folder and new_folder != old_folder:
        old_path = user_root_path(old_folder)
        new_path = os.path.join(BASE_STORAGE_DIR, new_folder)
        if os.path.exists(new_path):
            flash('A folder with that name already exists.')
            return redirect(url_for('browse_files'))
        if os.path.isdir(old_path):
            os.rename(old_path, new_path)
        session['user_folder'] = new_folder
    user['display_name'] = display_name
    user['folder'] = new_folder
    save_users(users)
    flash('Display name updated.')
    return redirect(url_for('browse_files'))

@app.route('/account/email-change/request', methods=['POST'])
@login_required
def request_email_change():
    new_email = normalized_email(request.form.get('new_email'))
    if not is_allowed_email(new_email):
        flash('Only an @iith.ac.in email address is allowed.')
        return redirect(url_for('browse_files'))
    users = load_users()
    username = session['username']
    user = users.get(username)
    if not isinstance(user, dict):
        abort(404)
    if new_email == normalized_email(user.get('email')):
        flash('That is already your current email address.')
        return redirect(url_for('browse_files'))
    if any(k != username and isinstance(v, dict) and normalized_email(v.get('email')) == new_email for k, v in users.items()):
        flash('That email is already used by another account.')
        return redirect(url_for('browse_files'))
    otp = f"{secrets.randbelow(1000000):06d}"
    created = time.time()
    try:
        send_email(new_email, 'Verify your new Cyber Drive email',
                   f"Your Cyber Drive email-change verification code is {otp}. It expires in 2 minutes. Your current email remains unchanged until verification succeeds.")
    except Exception:
        app.logger.warning('Email-change verification email could not be sent.', exc_info=True)
        flash('Could not send the verification code. Your current email has not changed; check SMTP settings.')
        return redirect(url_for('browse_files'))
    session['pending_email_change'] = {
        'email': new_email, 'otp_hash': generate_password_hash(otp),
        'expires': created + 120, 'attempts': 0,
    }
    flash('Verification code sent to the new email. Complete verification to replace your current email.')
    return redirect(url_for('verify_email_change'))

@app.route('/account/email-change/verify', methods=['GET', 'POST'])
@login_required
def verify_email_change():
    pending = session.get('pending_email_change')
    if not isinstance(pending, dict) or time.time() > float(pending.get('expires', 0)):
        session.pop('pending_email_change', None)
        flash('Email-change verification expired. Request a new code; your current email is unchanged.')
        return redirect(url_for('browse_files'))
    if request.method == 'GET':
        return render_template_string('''<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verify new email</title><style>body{font:16px system-ui;background:#070b13;color:#e2e8f0;display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(420px,90vw);box-sizing:border-box;background:#0b1220;border:1px solid #334155;border-radius:14px;padding:24px}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:10px;border-radius:8px}input{background:#070b13;color:#fff;border:1px solid #334155}button{background:#00e5ff;border:0;font-weight:bold}a{color:#67e8f9}</style></head><body><main class="card"><h2>Verify new email</h2><p>A 6-digit code was sent to <b>{{ email }}</b>. Your old email remains active until verification succeeds.</p><form method="post"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><label>Verification code</label><input name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus><button type="submit">Verify and change email</button></form><p><a href="/files/">Cancel</a></p></main></body></html>''', email=pending['email'])
    otp = request.form.get('otp', '').strip()
    if int(pending.get('attempts', 0)) >= 5:
        session.pop('pending_email_change', None)
        flash('Too many incorrect codes. Request a new code; your current email is unchanged.')
        return redirect(url_for('browse_files')), 429
    if not re.fullmatch(r'[0-9]{6}', otp) or not check_password_hash(pending['otp_hash'], otp):
        pending['attempts'] = int(pending.get('attempts', 0)) + 1
        session['pending_email_change'] = pending
        flash('Incorrect verification code. Your current email is unchanged.')
        return redirect(url_for('verify_email_change')), 400
    users = load_users()
    username = session['username']
    user = users.get(username)
    new_email = normalized_email(pending['email'])
    if not isinstance(user, dict):
        session.pop('pending_email_change', None)
        abort(404)
    if not is_allowed_email(new_email):
        session.pop('pending_email_change', None)
        flash('Only @iith.ac.in email addresses are allowed. Your current email is unchanged.')
        return redirect(url_for('browse_files'))
    if any(k != username and isinstance(v, dict) and normalized_email(v.get('email')) == new_email for k, v in users.items()):
        session.pop('pending_email_change', None)
        flash('That email is already used by another account. Your current email is unchanged.')
        return redirect(url_for('browse_files'))
    old_email = normalized_email(user.get('email'))
    user['email'] = new_email
    user['email_verified'] = True
    user['email_changed_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    save_users(users)
    session.pop('pending_email_change', None)

    # Notify both addresses; email delivery failures must not undo a verified change.
    if old_email and old_email != new_email:
        try:
            send_email(
                old_email,
                'Your Cyber Drive email address was changed',
                f"Hello {user.get('display_name') or 'there'},\n\n"
                f"The email address on your Cyber Drive account was changed to {new_email}. "
                "The old address is no longer associated with this account.\n\n"
                "If you did not make this change, contact your Cyber Drive administrator immediately.\n\n"
                "Thanks for being part of Cyber Drive, homie.\nTake care,\nCyber Drive"
            )
        except Exception:
            app.logger.warning('Email-change notification to the old address could not be sent.', exc_info=True)
    try:
        send_email(
            new_email,
            'Welcome to your updated Cyber Drive account',
            f"Hello {user.get('display_name') or 'there'},\n\n"
            "Your new email address has been verified and is now linked to your Cyber Drive account. "
            "Your files and account settings remain in place.\n\n"
            "Thanks for staying with Cyber Drive, homie.\nCheers,\nCyber Drive"
        )
    except Exception:
        app.logger.warning('Email-change welcome message could not be sent.', exc_info=True)

    flash('Email changed successfully. The old email has been removed from this account.')
    return redirect(url_for('browse_files'))

@app.route('/account/change-password', methods=['POST'])
@login_required
def change_password():
    users = load_users()
    username = session['username']
    user = users.get(username)
    if not isinstance(user, dict):
        abort(404)
    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    stored = user.get('password')
    if not isinstance(stored, str) or not check_password_hash(stored, current):
        flash('Current password is incorrect. Google-only accounts must set a password after confirming email first.')
        return redirect(url_for('browse_files'))
    if len(new) < 10 or new != confirm:
        flash('New passwords must match and contain at least 10 characters.')
        return redirect(url_for('browse_files'))
    user['password'] = generate_password_hash(new)
    user['provider'] = 'both' if user.get('google_sub') else 'email'
    save_users(users)
    flash('Password changed.')
    return redirect(url_for('browse_files'))

@app.route('/account/unlink-google', methods=['POST'])
@login_required
def unlink_google():
    users = load_users()
    user = users.get(session['username'])
    if not isinstance(user, dict):
        abort(404)
    if not user.get('password'):
        flash('Set an email/password login before unlinking Google, or you could lose access.')
        return redirect(url_for('browse_files'))
    user['google_sub'] = None
    user.pop('google_email', None)
    user['provider'] = 'email'
    save_users(users)
    flash('Google account unlinked.')
    return redirect(url_for('browse_files'))

@app.route('/account/delete', methods=['POST'])
@login_required
def delete_account():
    username = session.get('username', '')
    users = load_users()
    user = users.get(username)
    if not isinstance(user, dict):
        abort(404)
    confirm_email = normalized_email(request.form.get('confirm_email'))
    if request.form.get('delete_confirmation', '') != 'DELETE' or confirm_email != normalized_email(user.get('email')):
        flash('Account deletion cancelled: confirmation text or email did not match.')
        return redirect(url_for('browse_files'))
    stored_password = user.get('password')
    current_password = request.form.get('current_password', '')
    if stored_password and (not current_password or not check_password_hash(stored_password, current_password)):
        flash('Account deletion failed: current password is incorrect.')
        return redirect(url_for('browse_files'))

    farewell_email = normalized_email(user.get('email'))
    if farewell_email:
        try:
            send_email(
                farewell_email,
                'Goodbye from Cyber Drive',
                f"Hello {user.get('display_name') or 'there'},\n\n"
                "Your Cyber Drive account deletion was requested and has been completed. "
                "The account and its stored files are being removed, and you will no longer be able to sign in.\n\n"
                "Thank you for giving Cyber Drive a try. We appreciate you, homie, and wish you the best in whatever you build next.\n\n"
                "Take care,\nCyber Drive"
            )
        except Exception:
            app.logger.warning('Account-deletion farewell email could not be sent.', exc_info=True)

    folder = safe_folder_name(user.get('folder', ''))
    if folder:
        folder_path = user_root_path(folder)
        if os.path.isdir(folder_path) and not os.path.islink(folder_path):
            shutil.rmtree(folder_path)
    users.pop(username, None)
    save_users(users)
    log_path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
    try:
        if os.path.isfile(log_path): os.remove(log_path)
        transfer_path = transfer_history_path(username)
        if os.path.isfile(transfer_path): os.remove(transfer_path)
    except OSError:
        app.logger.warning('Could not remove deleted account activity log.', exc_info=True)
    session.clear()
    return redirect(url_for('login'))

def record_user_activity(username, event, message):
    """Append a client-visible account event to the user's activity log."""
    if not username:
        return
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)
    path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
    now = datetime.now(timezone.utc)
    try:
        events = []
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                old = json.load(f)
            if isinstance(old, list): events = old
        cutoff = now - timedelta(days=10)
        kept = []
        for ev in events:
            try:
                if datetime.fromisoformat(ev.get('timestamp', '').replace('Z', '+00:00')) >= cutoff:
                    kept.append(ev)
            except Exception:
                continue
        kept.append({'event': str(event)[:40], 'method': str(message)[:500], 'timestamp': now.isoformat(timespec='seconds')})
        temp = path + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f: json.dump(kept[-500:], f, ensure_ascii=False, indent=2)
        try: os.chmod(temp, 0o600)
        except OSError: pass
        os.replace(temp, path)
    except (OSError, ValueError, TypeError):
        app.logger.exception('ACTIVITY LOG | failed to record account=%s event=%s', username, event)

def record_transfer_event(username, action, item, status, size=''):
    """Append server-verified transfer outcomes to the user's 10-day history."""
    if not username:
        return
    path = transfer_history_path(username)
    now = datetime.now(timezone.utc)
    try:
        events = []
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                old = json.load(f)
            if isinstance(old, list): events = old
        cutoff = now - timedelta(days=10)
        kept = []
        for ev in events:
            try:
                if datetime.fromisoformat(ev.get('timestamp', '').replace('Z','+00:00')) >= cutoff:
                    kept.append(ev)
            except Exception: pass
        kept.append({'action':str(action)[:32], 'item':str(item)[:500], 'status':status if status in {'Success','Failed','Cancelled'} else 'Failed', 'size':str(size)[:32], 'timestamp':now.isoformat(timespec='seconds')})
        temp=path+'.tmp'
        with open(temp,'w',encoding='utf-8') as f: json.dump(kept[-500:],f,ensure_ascii=False)
        os.replace(temp,path)
        try: os.chmod(path,0o600)
        except OSError: pass
        if str(action).lower() in {'upload','download'}:
            activity_path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
            activity=[]
            try:
                with open(activity_path,'r',encoding='utf-8') as af:
                    prior=json.load(af)
                if isinstance(prior,list): activity=prior
            except (OSError,ValueError): pass
            activity.append({'event':str(action).lower(),'method':f'{status}: {str(item)[:160]} ({size})','timestamp':now.isoformat(timespec='seconds')})
            with open(activity_path+'.tmp','w',encoding='utf-8') as af: json.dump(activity[-500:],af,ensure_ascii=False)
            os.replace(activity_path+'.tmp',activity_path)
    except (OSError, ValueError):
        app.logger.exception('Could not record server-side transfer event')


def transfer_history_path(username):
    """Per-account transfer log; account names never appear in the filename."""
    return os.path.join(SESSION_LOG_DIR, 'transfer_' + hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')

@app.route('/api/transfer-history', methods=['GET', 'POST'])
@login_required
def transfer_history():
    username = session['username']
    path = transfer_history_path(username)
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        action = str(data.get('action', 'Transfer'))[:32]
        item = str(data.get('item', 'Transfer'))[:500]
        status = str(data.get('status', 'Failed'))
        if status not in {'Success', 'Failed', 'Cancelled'}:
            status = 'Failed'
        size = str(data.get('size', ''))[:32]
        now = datetime.now(timezone.utc)
        try:
            events = []
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8') as f:
                    old = json.load(f)
                if isinstance(old, list): events = old
            cutoff = now - timedelta(days=10)
            kept = []
            for ev in events:
                try:
                    stamp = datetime.fromisoformat(ev.get('timestamp', '').replace('Z', '+00:00'))
                    if stamp >= cutoff: kept.append(ev)
                except Exception: pass
            kept.append({'action': action, 'item': item, 'status': status, 'size': size, 'timestamp': now.isoformat(timespec='seconds')})
            kept = kept[-500:]
            # Keep the account activity log in sync with transfer outcomes as well.
            if action.lower() in {'upload', 'download'}:
                activity_path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
                activity = []
                try:
                    with open(activity_path, 'r', encoding='utf-8') as af:
                        old_activity = json.load(af)
                    if isinstance(old_activity, list): activity = old_activity
                except (OSError, ValueError): pass
                activity.append({'event': action.lower(), 'method': f'{status}: {item[:160]} ({size})', 'timestamp': now.isoformat(timespec='seconds')})
                with open(activity_path + '.tmp', 'w', encoding='utf-8') as af: json.dump(activity[-500:], af, ensure_ascii=False)
                os.replace(activity_path + '.tmp', activity_path)
            os.makedirs(SESSION_LOG_DIR, exist_ok=True)
            temp = path + '.tmp'
            with open(temp, 'w', encoding='utf-8') as f: json.dump(kept, f, ensure_ascii=False)
            os.replace(temp, path)
            try: os.chmod(path, 0o600)
            except OSError: pass
            return jsonify({'ok': True})
        except (OSError, ValueError):
            app.logger.exception('Could not write transfer history')
            return jsonify({'error': 'Could not save transfer history.'}), 500
    events = []
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f: raw = json.load(f)
            cutoff = datetime.now(timezone.utc) - timedelta(days=10)
            for ev in raw if isinstance(raw, list) else []:
                try:
                    stamp = datetime.fromisoformat(ev.get('timestamp', '').replace('Z', '+00:00'))
                    if stamp >= cutoff:
                        events.append({'action': str(ev.get('action','Transfer'))[:32], 'item': str(ev.get('item','Transfer'))[:500], 'status': ev.get('status','Failed'), 'size': str(ev.get('size',''))[:32], 'time': stamp.astimezone().strftime('%Y-%m-%d %H:%M:%S')})
                except Exception: pass
        except (OSError, ValueError): pass
    events.sort(key=lambda ev: ev['time'], reverse=True)
    return jsonify({'events': events})

@app.route('/api/transfer-history/clear', methods=['POST'])
@login_required
def clear_transfer_history():
    try:
        path = transfer_history_path(session['username'])
        if os.path.isfile(path): os.remove(path)
        return jsonify({'ok': True})
    except OSError:
        app.logger.exception('Could not clear transfer history')
        return jsonify({'error': 'Could not clear your transfer history.'}), 500


@app.route('/api/session-activity')
@login_required
def session_activity():
    username = session['username']
    path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
    events = []
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            cutoff = datetime.now(timezone.utc) - timedelta(days=10)
            for item in raw if isinstance(raw, list) else []:
                try:
                    stamp = datetime.fromisoformat(item.get('timestamp','').replace('Z','+00:00'))
                    if stamp >= cutoff:
                        events.append({'event':str(item.get('event','activity'))[:40],'method':str(item.get('method','unknown'))[:500],'time':stamp.astimezone().strftime('%Y-%m-%d %H:%M:%S')})
                except Exception:
                    continue
        except (OSError, ValueError):
            pass
    events.sort(key=lambda x:x['time'], reverse=True)
    return jsonify({'events':events})


@app.route('/api/session-activity/clear', methods=['POST'])
@login_required
def clear_session_activity():
    username = session['username']
    path = os.path.join(SESSION_LOG_DIR, hashlib.sha256(username.casefold().encode()).hexdigest() + '.json')
    try:
        if os.path.isfile(path):
            os.remove(path)
        return jsonify({'ok': True})
    except OSError:
        app.logger.exception('Could not clear session activity log')
        return jsonify({'error': 'Could not clear your activity log. Please try again.'}), 500


@app.route('/api/upload-reservation', methods=['POST'])
@login_required
def api_upload_reservation():
    data = request.get_json(silent=True) or {}
    try:
        size_bytes = int(data.get('bytes', 0))
        token = reserve_upload(session['username'], size_bytes)
        return jsonify({'ok': True, 'token': token})
    except ValueError as exc:
        app.logger.warning('UPLOAD REJECTED BEFORE START | account=%s | reason=%s', session.get('username', 'unknown'), str(exc))
        record_transfer_event(session.get('username', ''), 'Upload', 'Preflight storage check', 'Failed', str(data.get('bytes', 'unknown')) + ' bytes')
        return jsonify({'ok': False, 'error': str(exc)}), 413
    except Exception:
        app.logger.exception('UPLOAD PREFLIGHT ERROR | account=%s', session.get('username', 'unknown'))
        record_transfer_event(session.get('username', ''), 'Upload', 'Preflight storage check', 'Failed', str(data.get('bytes', 'unknown')) + ' bytes')
        return jsonify({'ok': False, 'error': 'Could not reserve storage. Please retry.'}), 500


@app.route('/api/upload-reservation/release', methods=['POST'])
@login_required
def api_release_upload_reservation():
    data = request.get_json(silent=True) or {}
    release_upload_reservation(str(data.get('token', '')), session['username'])
    return jsonify({'ok': True})




@app.route('/admin/files', methods=['GET'])
@admin_required
def admin_manage_files():
    users_db = load_users()
    user_list = []
    for username, user in users_db.items():
        if not isinstance(user, dict):
            continue
        folder = safe_folder_name(user.get('folder', ''))
        if folder:
            user_list.append({'username': str(username), 'folder': folder})
    user_list.sort(key=lambda item: item['username'].casefold())
    selected = request.args.get('username', '')
    selected_user = next((item for item in user_list if item['username'] == selected), None)
    files = []
    error = None
    if selected_user:
        root = user_root_path(selected_user['folder'])
        if os.path.isdir(root) and not os.path.islink(root):
            try:
                for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
                    # Never descend into symlink directories.
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current, d))]
                    for name in names:
                        full_path = os.path.join(current, name)
                        if os.path.islink(full_path) or not os.path.isfile(full_path):
                            continue
                        rel = os.path.relpath(full_path, root).replace(os.sep, '/')
                        try:
                            size = os.path.getsize(full_path)
                        except OSError:
                            size = 0
                        files.append({'path': rel, 'size': size})
            except OSError:
                app.logger.exception('Admin could not list files for %r', selected)
                error = 'Could not read this account’s file list. Check the server logs.'
    files.sort(key=lambda item: item['path'].casefold())
    page = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Manage client files · Cyber Drive</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#070b13;color:#e2e8f0;font:14px system-ui}.wrap{max-width:1100px;margin:auto;padding:24px 16px 50px}.panel{background:#0b1220;border:1px solid #223044;border-radius:14px;padding:18px;margin:16px 0}.muted{color:#94a3b8}.btn{border:1px solid #334155;background:#111c2d;color:#e2e8f0;padding:9px 12px;border-radius:8px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px}.primary{background:#00e5ff;color:#041018;border-color:#00e5ff;font-weight:800}.danger{border-color:#7f1d1d;color:#fecaca}.top,.file{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.file{border-top:1px solid #263448;padding:12px 0}.file:first-child{border-top:0}.path{overflow-wrap:anywhere;flex:1;min-width:180px}.size{color:#94a3b8;white-space:nowrap}select{padding:10px;border-radius:8px;border:1px solid #334155;background:#070b13;color:#fff;max-width:100%;min-width:220px}.notice{padding:11px;border:1px solid #155e75;border-radius:9px;background:#083344;color:#a5f3fc;margin:12px 0}.error{border-color:#7f1d1d;color:#fecaca;background:#2b1016}h1{margin:4px 0 8px;font-size:26px}h2{font-size:18px}@media(max-width:560px){.wrap{padding:14px 10px}.panel{padding:13px}.size{width:100%}}
</style></head><body><main class="wrap"><header class="top"><div><div class="muted">Cyber Drive · Administration</div><h1>Manage client files</h1><p class="muted">Delete individual files without deleting the client account. Deleted files cannot be recovered.</p></div><a class="btn" href="/admin">← Back to dashboard</a></header>
{% if notice %}<div class="notice">{{ notice }}</div>{% endif %}{% if error %}<div class="notice error">{{ error }}</div>{% endif %}
<section class="panel"><form method="get" action="/admin/files"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><label for="username"><b>Client account</b></label><div class="top" style="justify-content:flex-start;margin-top:9px"><select id="username" name="username" required><option value="">Choose an account…</option>{% for u in users %}<option value="{{ u.username }}" {% if selected==u.username %}selected{% endif %}>{{ u.username }}</option>{% endfor %}</select><button class="btn primary" type="submit">Show files</button></div></form></section>
{% if selected_user %}<section class="panel"><h2>{{ selected_user.username }} — stored files</h2><p class="muted">{{ files|length }} file(s) · Total shown: {{ total_size }}</p>{% for f in files %}<div class="file"><div class="path">📄 {{ f.path }}</div><div class="size">{{ f.size_label }}</div><form method="post" action="/admin/files/delete" onsubmit="return confirm('Permanently delete {{ f.path|e }} from {{ selected_user.username|e }}? This cannot be undone.');"><input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="username" value="{{ selected_user.username }}"><input type="hidden" name="path" value="{{ f.path }}"><button class="btn danger" type="submit">🗑 Delete file</button></form></div>{% else %}<p class="muted">This account has no regular files to display.</p>{% endfor %}</section>{% endif %}</main></body></html>"""
    total_size = sum(item['size'] for item in files)
    for item in files:
        n = item['size']
        item['size_label'] = f'{n / (1024**2):.2f} MB' if n >= 1024**2 else (f'{n / 1024:.1f} KB' if n >= 1024 else f'{n} B')
    total_label = f'{total_size / (1024**3):.3f} GB' if total_size >= 1024**3 else f'{total_size / (1024**2):.2f} MB'
    return render_template_string(page, users=user_list, selected=selected, selected_user=selected_user,
                                  files=files, total_size=total_label, notice=request.args.get('notice'), error=error)


@app.route('/admin/files/delete', methods=['POST'])
@admin_required
def admin_delete_client_file():
    username = request.form.get('username', '')
    rel_path = request.form.get('path', '')
    users = load_users()
    user = users.get(username)
    if not isinstance(user, dict):
        return redirect(url_for('admin_manage_files', error='That client account no longer exists.'))
    folder = safe_folder_name(user.get('folder', ''))
    if not folder or not rel_path or os.path.isabs(rel_path) or '\\' in rel_path or '\x00' in rel_path:
        return redirect(url_for('admin_manage_files', username=username, error='Invalid file path.'))
    root = user_root_path(folder)
    # Resolve the parent separately and refuse symlinks, traversal, and directories.
    parent_rel, basename = os.path.split(rel_path)
    if not basename or basename in {'.', '..'}:
        return redirect(url_for('admin_manage_files', username=username, error='Invalid file path.'))
    parent = resolve_user_path(root, parent_rel)
    target = os.path.join(parent, basename)
    try:
        if os.path.commonpath([os.path.realpath(root), os.path.realpath(target)]) != os.path.realpath(root):
            abort(403)
        if os.path.islink(target) or not os.path.isfile(target):
            return redirect(url_for('admin_manage_files', username=username, error='File not found or not a regular file.'))
        os.unlink(target)
        record_admin_event('Deleted client file', f'account={username}; path={rel_path}')
        app.logger.warning('Admin deleted client file for %r: %r', username, rel_path)
        return redirect(url_for('admin_manage_files', username=username, notice=f'Deleted {rel_path}.'))
    except OSError:
        app.logger.exception('Admin could not delete client file for %r', username)
        return redirect(url_for('admin_manage_files', username=username, error='Could not delete the file. Check server logs.'))


@app.route('/admin/wipe-data', methods=['POST'])
@admin_required
def admin_wipe_data():
    users = load_users()
    wiped = 0
    errors = []
    for username, user in users.items():
        if not isinstance(user, dict):
            continue
        folder = safe_folder_name(user.get('folder', ''))
        if not folder:
            continue
        root = user_root_path(folder)
        if os.path.isdir(root) and not os.path.islink(root):
            try:
                for entry in os.scandir(root):
                    path = entry.path
                    if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                        os.unlink(path)
                    elif entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(path)
                wiped += 1
            except OSError:
                errors.append(str(username))
                app.logger.exception('Could not wipe client data for %r', username)
    record_admin_event('Wiped client data', f'Cleared storage for {wiped} account(s); errors={len(errors)}')
    if errors:
        return redirect(url_for('admin_dashboard', error=f'Data wipe completed with errors for {len(errors)} account(s). Check server logs.'))
    return redirect(url_for('admin_dashboard', notice=f'Wiped stored files for {wiped} account(s). Accounts and settings were preserved.'))


@app.route('/files/', defaults={'req_path': ''}, methods=['GET', 'POST'])
@app.route('/files/<path:req_path>', methods=['GET', 'POST'])
@login_required
def browse_files(req_path=''):
    user_folder_name = session.get('user_folder', '')
    user_root = user_root_path(user_folder_name)
    # A missing account home directory should not strand the user on a 404.
    # Recreate only the account's top-level home; missing nested paths remain 404s.
    if not os.path.exists(user_root) and not req_path:
        os.makedirs(user_root, exist_ok=True)
    abs_path = resolve_user_path(user_root, req_path)
    if os.path.islink(abs_path):
        abort(403)

    if os.path.isfile(abs_path):
        as_attachment = request.args.get('download') == '1'
        if as_attachment:
            record_transfer_event(session.get('username', ''), 'Download', os.path.basename(abs_path), 'Success', str(os.path.getsize(abs_path)))
        return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path), as_attachment=as_attachment)

    if request.args.get('download') == '1' and os.path.isdir(abs_path):
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_STORED) as zf:
            root_len = len(abs_path)
            for root, dirs, files in os.walk(abs_path, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path) and not os.path.islink(file_path):
                        parent_dir = file_path[root_len:].lstrip(os.sep)
                        zf.write(file_path, parent_dir)
        memory_file.seek(0)
        folder_name = os.path.basename(abs_path) or user_folder_name
        record_transfer_event(session.get('username', ''), 'Download', folder_name + '.zip', 'Success', str(memory_file.getbuffer().nbytes))
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{folder_name}.zip"
        )

    current_folder_size = get_folder_size(user_root)
    error_msg = None

    if request.method == 'POST':
        action = request.form.get('action')
        target_dir = abs_path if os.path.isdir(abs_path) else os.path.dirname(abs_path)
        target_dir = resolve_user_path(user_root, os.path.relpath(target_dir, user_root))
        if not os.path.isdir(target_dir) or os.path.islink(target_dir):
            abort(400, description='Invalid destination folder.')

        if action == 'upload':
            uploaded_files = request.files.getlist('file')
            total_upload_size = 0
            for f in uploaded_files:
                if f and f.filename:
                    f.seek(0, os.SEEK_END); total_upload_size += f.tell(); f.seek(0)
            username = session.get('username', '')
            reservation_token = str(request.form.get('reservation_token', ''))
            with UPLOAD_RESERVATION_LOCK:
                reservation = UPLOAD_RESERVATIONS.get(reservation_token)
                valid_reservation = bool(reservation and reservation.get('username') == username and reservation.get('bytes') == total_upload_size)
            if not valid_reservation:
                app.logger.warning('UPLOAD REJECTED | account=%s | reason=missing_or_expired_reservation | bytes=%.3f GB', username, total_upload_size/1024**3)
                record_transfer_event(username, 'Upload', ', '.join(secure_filename(f.filename) for f in uploaded_files if f and f.filename), 'Failed', str(total_upload_size))
                return jsonify({'status':'error','message':'Upload was rejected because its storage reservation expired or did not match the selected files. Select the files again; storage will be checked before upload starts.'}), 409
            try:
                current_user_record = load_users().get(username, {})
                user_quota_bytes = effective_user_quota(current_user_record)
                current_user_used_bytes = get_folder_size(user_root)
                if current_user_used_bytes + total_upload_size > user_quota_bytes:
                    available_gb = round(max(0, user_quota_bytes - current_user_used_bytes) / (1024**3), 3)
                    app.logger.warning('UPLOAD REJECTED AFTER BODY RECEIVED | account=%s | reason=user_quota_changed | upload=%.3f GB | used=%.3f GB | quota=%.3f GB', username, total_upload_size/1024**3, current_user_used_bytes/1024**3, user_quota_bytes/1024**3)
                    record_transfer_event(username, 'Upload', ', '.join(secure_filename(f.filename) for f in uploaded_files if f and f.filename), 'Failed', str(total_upload_size))
                    return jsonify({'status': 'error', 'message': f'Storage limit exceeded. Available before this upload: {available_gb} GB. The upload was rejected.'}), 413
                cloud_used_now = cloud_usage_bytes()
                cloud_cap_now = enforce_dynamic_cloud_limit()
                if cloud_used_now + total_upload_size > cloud_cap_now:
                    app.logger.warning('UPLOAD REJECTED AFTER BODY RECEIVED | account=%s | reason=cloud_cap_changed | upload=%.3f GB | cloud_used=%.3f GB | cap=%.3f GB', username, total_upload_size/1024**3, cloud_used_now/1024**3, cloud_cap_now/1024**3)
                    record_transfer_event(username, 'Upload', ', '.join(secure_filename(f.filename) for f in uploaded_files if f and f.filename), 'Failed', str(total_upload_size))
                    return jsonify({'status':'error','message':'The server storage safety limit changed while this upload was in progress. The upload was rejected; please retry after checking available storage.'}), 413
                for file in uploaded_files:
                    if file and file.filename:
                        safe_name = secure_filename(file.filename)
                        if not safe_name or safe_name.startswith('.'):
                            continue
                        unique_filename = get_unique_filename(target_dir, safe_name)
                        destination = os.path.join(target_dir, unique_filename)
                        try:
                            with open(destination, 'xb') as out_file:
                                shutil.copyfileobj(file.stream, out_file, length=1024 * 1024)
                        except FileExistsError:
                            unique_filename = get_unique_filename(target_dir, safe_name)
                            destination = os.path.join(target_dir, unique_filename)
                            with open(destination, 'xb') as out_file:
                                shutil.copyfileobj(file.stream, out_file, length=1024 * 1024)
                        current_folder_size += os.path.getsize(destination)
                record_transfer_event(username, 'Upload', ', '.join(secure_filename(f.filename) for f in uploaded_files if f and f.filename), 'Success', str(total_upload_size))
                app.logger.info('UPLOAD COMPLETE | account=%s | files=%s | bytes=%s | size=%.3f GB', username, len([f for f in uploaded_files if f and f.filename]), total_upload_size, total_upload_size/1024**3)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'success', 'message': 'Upload completed.'})
            finally:
                release_upload_reservation(reservation_token, username)

        elif action == 'create_folder':
            folder_name = safe_folder_name(request.form.get('folder_name', ''))
            if not folder_name:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Enter a valid folder name.'}), 400
                error_msg = 'Enter a valid folder name.'
            else:
                new_folder_path = resolve_user_path(user_root, os.path.relpath(os.path.join(target_dir, folder_name), user_root))
                if os.path.exists(new_folder_path):
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'status': 'error', 'message': 'A file or folder with that name already exists.'}), 409
                    error_msg = 'A file or folder with that name already exists.'
                else:
                    os.mkdir(new_folder_path)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and not error_msg:
                return jsonify({'status': 'success'})

        elif action == 'rename':
            item_rel_path = request.form.get('item_path', '').strip()
            new_name = safe_folder_name(request.form.get('new_name', ''))
            if not item_rel_path or not new_name:
                return jsonify({'status': 'error', 'message': 'Enter a valid name.'}), 400
            old_path = resolve_user_path(user_root, item_rel_path)
            if old_path == user_root or not os.path.exists(old_path) or os.path.islink(old_path):
                return jsonify({'status': 'error', 'message': 'That item cannot be renamed.'}), 400
            parent_path = os.path.realpath(os.path.dirname(old_path))
            if os.path.commonpath([os.path.realpath(user_root), parent_path]) != os.path.realpath(user_root):
                abort(403)
            new_path = os.path.join(parent_path, new_name)
            if os.path.exists(new_path):
                return jsonify({'status': 'error', 'message': 'A file or folder with that name already exists.'}), 409
            try:
                os.rename(old_path, new_path)
            except OSError:
                return jsonify({'status': 'error', 'message': 'Rename failed. Check the name and try again.'}), 400
            return jsonify({'status': 'success'})

        elif action == 'delete':
            items_to_delete = request.form.getlist('item_path')
            if not items_to_delete and request.form.get('item_path'):
                items_to_delete = [request.form.get('item_path')]

            for item_p in items_to_delete:
                full_item_path = resolve_user_path(user_root, item_p)
                if full_item_path != user_root and not os.path.islink(full_item_path):
                    if os.path.isdir(full_item_path):
                        shutil.rmtree(full_item_path)
                    elif os.path.isfile(full_item_path):
                        os.remove(full_item_path)

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'success'})

        if not error_msg and request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            return redirect(url_for('browse_files', req_path=req_path))

    if os.path.isdir(abs_path):
        try:
            raw_items = os.listdir(abs_path)
        except PermissionError:
            return "<h3>Access Denied</h3>", 403

        items = []
        for item in sorted(raw_items):
            if item.startswith('.'):
                continue
            
            full_item_path = os.path.join(abs_path, item)
            if os.path.islink(full_item_path):
                continue
            full_item_path = os.path.realpath(full_item_path)
            rel_path = os.path.relpath(full_item_path, user_root)
            file_url = url_for("browse_files", req_path=rel_path)

            is_dir = os.path.isdir(full_item_path)
            size_str = format_size(get_folder_size(full_item_path) if is_dir else os.path.getsize(full_item_path))

            media_type = None
            ext = os.path.splitext(item)[1].lower()
            if ext in IMAGE_EXTS: media_type = "image"
            elif ext in AUDIO_EXTS: media_type = "audio"
            elif ext in VIDEO_EXTS: media_type = "video"
            elif ext in DOCUMENT_EXTS: media_type = "document"
            elif ext in {e.lower() for e in CODE_EXTS}: media_type = "code"

            items.append({
                'name': item,
                'rel_path': rel_path,
                'file_url': file_url,
                'is_dir': is_dir,
                'size_str': size_str,
                'media_type': media_type
            })

        parent_url = None
        if abs_path != user_root:
            parent_path = os.path.relpath(os.path.dirname(abs_path), user_root)
            if parent_path == '.': parent_path = ''
            parent_url = url_for("browse_files", req_path=parent_path)

        used_bytes = current_folder_size
        current_user_record = load_users().get(session.get('username', ''), {})
        quota_bytes = effective_user_quota(current_user_record)
        quota_gb = int(quota_bytes // (1024 * 1024 * 1024))
        used_bytes = get_folder_size(user_root)
        available_bytes = max(0, quota_bytes - used_bytes)
        used_gb = round(used_bytes / (1024 * 1024 * 1024), 2)
        storage_pct = min(100, int((used_bytes / quota_bytes) * 100))
        pending_storage_requests = load_storage_requests()
        storage_request_pending = session.get('username', '') in pending_storage_requests

        if storage_pct >= 85:
            bar_color = "#ef4444"
            glow_color = "rgba(239, 68, 68, 0.8)"
        elif storage_pct >= 60:
            bar_color = "#f59e0b"
            glow_color = "rgba(245, 158, 11, 0.8)"
        else:
            bar_color = "#10b981"
            glow_color = "rgba(16, 185, 129, 0.8)"

        folder_title = clean_path_display(req_path, 'Home')

        return render_template_string(MAIN_TEMPLATE,
            username=session['username'],
            account_email=load_users().get(session.get('username', ''), {}).get('email', ''),
            account_display_name=(load_users().get(session.get('username', ''), {}).get('display_name') or 'My Drive'),
            account_google=bool(load_users().get(session.get('username', ''), {}).get('google_sub')),
            user_folder_name=user_folder_name,
            folder_title=folder_title,
            current_rel_path=req_path,
            parent_url=parent_url,
            items=items,
            used_gb=used_gb,
            storage_pct=storage_pct,
            bar_color=bar_color,
            glow_color=glow_color,
            available_bytes=available_bytes,
            quota_gb=quota_gb,
            storage_request_pending=storage_request_pending,
            error_msg=error_msg
        )

    # Ensure Flask always receives a valid response if the resolved path is missing.
    abort(404, description='The requested file or folder does not exist.')

if __name__ == '__main__':
    # Development only. For internet access, run behind a TLS reverse proxy (e.g. Caddy)
    # and set CYBER_DRIVE_HTTPS=1. Do not expose Flask's development server directly.
    app.run(host=os.environ.get('CYBER_DRIVE_HOST', '0.0.0.0'),
            port=int(os.environ.get('CYBER_DRIVE_PORT', '80')),
            threaded=True, debug=False)
