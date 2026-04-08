"""
SecureVault — Secure Cookie & Digital Signature System
=======================================================
Part A : HMAC (Replaced with simple version)
Part B : RSA-2048 key-pair generation, file signing, verification
Bonus  : Key Substitution & Message/Key Substitution attacks
"""

import os, hashlib, hmac, time
from datetime import datetime
from flask import Flask, render_template, request, redirect, make_response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.jinja_env.globals["enumerate"] = enumerate

# ─────────────────────────────────────────────────────────────
# PART A — NEW HMAC (YOUR CODE)
# ─────────────────────────────────────────────────────────────

SECRET_KEY = b'my_super_secret_key'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        '''

    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'user' and password == 'password':
        role = 'user'
        expires = int(time.time()) + 300

        payload = f"{username}|{role}|{expires}"
        mac = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()

        resp = make_response(redirect('/protected'))
        resp.set_cookie('auth_cookie', payload, httponly=True)
        resp.set_cookie('auth_mac', mac, httponly=True)
        return resp
    else:
        return "Invalid credentials!", 401


@app.route('/protected')
def protected():
    payload = request.cookies.get('auth_cookie')
    mac = request.cookies.get('auth_mac')

    if not payload or not mac:
        return "No cookie, access denied!", 403

    expected_mac = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_mac, mac):
        return "Tampering detected! Access denied!", 403

    try:
        username, role, expires = payload.split('|')
    except:
        return "Invalid cookie format!", 403

    if int(expires) < int(time.time()):
        return "Session expired!", 403

    return f"Access granted! Welcome {username}, role: {role}"


@app.route('/')
def home():
    return "Server is running 🚀"


# ─────────────────────────────────────────────────────────────
# PART B — (UNCHANGED 100%)
# ─────────────────────────────────────────────────────────────

KEY_STORE   = {"private_key": None, "public_key": None}
SIGNED_FILES = {}

os.makedirs("uploads",      exist_ok=True)
os.makedirs("signed_files", exist_ok=True)


@app.route("/vault")
def vault():
    return render_template("vault.html",
        pub_pem       = _pub_pem(),
        signed_files  = list(SIGNED_FILES.keys()),
        active_tab    = "keys")

@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_STORE["private_key"] = priv
    KEY_STORE["public_key"]  = priv.public_key()
    SIGNED_FILES.clear()

    with open("signed_files/private_key.pem", "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open("signed_files/public_key.pem", "wb") as f:
        f.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    fingerprint = hashlib.sha256(
        KEY_STORE["public_key"].public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()

    return render_template("vault.html",
        pub_pem      = _pub_pem(),
        signed_files = list(SIGNED_FILES.keys()),
        active_tab   = "keys",
        msg          = f"RSA-2048 key pair generated. Fingerprint: {fingerprint[:32]}…",
        msg_type     = "success")


@app.route("/sign-file", methods=["POST"])
def sign_file():
    if not KEY_STORE["private_key"]:
        return _vault_msg("sign", "Generate a key pair first.", "danger")

    f = request.files.get("file")
    if not f or f.filename == "":
        return _vault_msg("sign", "No file selected.", "danger")

    content   = f.read()
    filename  = f.filename

    signature = KEY_STORE["private_key"].sign(
        content,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    SIGNED_FILES[filename] = {"original_content": content, "signature": signature}

    safe = filename.replace("/", "_")
    with open(f"signed_files/{safe}", "wb") as fh:
        fh.write(content)
    with open(f"signed_files/{safe}.sig", "wb") as fh:
        fh.write(signature)
    with open(f"signed_files/{safe}.pubkey.pem", "wb") as fh:
        fh.write(KEY_STORE["public_key"].public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    return render_template("vault.html",
        pub_pem      = _pub_pem(),
        signed_files = list(SIGNED_FILES.keys()),
        active_tab   = "sign",
        msg          = f"File '{filename}' signed and saved.",
        msg_type     = "success")


@app.route("/verify-file", methods=["POST"])
def verify_file():
    filename = request.form.get("filename")
    mode     = request.form.get("mode", "original")

    if not filename or filename not in SIGNED_FILES:
        return _vault_msg("verify", "File not found.", "danger")

    stored_sig       = SIGNED_FILES[filename]["signature"]
    original_content = SIGNED_FILES[filename]["original_content"]

    if mode == "original":
        data = original_content
    else:
        data = original_content + b"\n[TAMPERED]"

    try:
        KEY_STORE["public_key"].verify(
            stored_sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        result = {"ok": True,  "msg": "✓ Signature VALID"}
    except InvalidSignature:
        result = {"ok": False, "msg": "✕ Signature INVALID"}

    return render_template("vault.html",
        pub_pem=_pub_pem(),
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="verify",
        verify_result=result)


# ─────────────────────────────────────────────────────────────
# BONUS (UNCHANGED)
# ─────────────────────────────────────────────────────────────

@app.route("/attack/key-sub", methods=["POST"])
def attack_key_sub():
    message = request.form.get("message", "Grant admin access").encode()

    atk_priv = rsa.generate_private_key(65537, 2048)
    atk_pub  = atk_priv.public_key()
    atk_sig  = atk_priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    try:
        atk_pub.verify(atk_sig, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        passes = True
    except InvalidSignature:
        passes = False

    result = {
        "name": "Key Substitution Attack",
        "passes": passes
    }

    return render_template("vault.html",
        pub_pem=_pub_pem(),
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="bonus",
        attack_result=result)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _pub_pem():
    if KEY_STORE["public_key"] is None:
        return None
    return KEY_STORE["public_key"].public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def _vault_msg(tab, msg, msg_type):
    return render_template("vault.html",
        pub_pem=_pub_pem(),
        signed_files=list(SIGNED_FILES.keys()),
        active_tab=tab,
        msg=msg,
        msg_type=msg_type)

@app.errorhandler(404)
def not_found(_):
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True, port=5000)