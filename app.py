"""
CipherGuard — Secure Cookie & Digital Signature System
=======================================================
Part A : HMAC-SHA256 cookie protection
Part B : RSA-2048 key-pair generation + digital signing / verification
Bonus  : Key Substitution & Message/Key Substitution attacks (Wong p.150)
"""

from flask import Flask, render_template, request, redirect, make_response, session
import hmac
import hashlib
import time
import os
import json
from flask import Flask, render_template, request
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__, template_folder="templates")
app = Flask(__name__)
app.secret_key = os.urandom(32)

# ─── Part A : MAC secret — NEVER sent to client ───────────────────────────────
MAC_SECRET = b"cipherguard_secret_key_never_expose_this_$3cur3!"

# ─── In-memory stores ─────────────────────────────────────────────────────────
KEY_STORE = {
    "private_key": None,
    "public_key": None,
}
SIGNED_FILES = {}   # filename -> {"signature": bytes, "content": bytes}

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PART A — HMAC Cookie Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def generate_mac(data: str) -> str:
    """Generate HMAC-SHA256 tag for cookie payload."""
    return hmac.new(MAC_SECRET, data.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_mac(data: str, received_mac: str) -> bool:
    """Constant-time HMAC comparison (prevents timing attacks)."""
    expected = generate_mac(data)
    return hmac.compare_digest(expected, received_mac)


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — Part A
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "user")

        if not username:
            return render_template("login.html", error="Username is required.")

        # Clamp role to known values (defense-in-depth)
        if role not in ("user", "admin"):
            role = "user"

        expiration = str(int(time.time()) + 300)          # 5-minute session
        cookie_payload = f"{username}|{role}|{expiration}"
        mac_tag = generate_mac(cookie_payload)

        response = make_response(redirect("/protected"))
        # HttpOnly flag prevents JS access; SameSite=Strict prevents CSRF
        response.set_cookie("session_data", cookie_payload, httponly=True, samesite="Strict")
        response.set_cookie("session_mac",  mac_tag,        httponly=True, samesite="Strict")
        return response

    return render_template("login.html")


@app.route("/protected")
def protected():
    cookie_payload = request.cookies.get("session_data")
    mac_tag        = request.cookies.get("session_mac")

    # ── Missing cookies ──
    if not cookie_payload or not mac_tag:
        return render_template(
            "tampered.html",
            reason="no session cookies found — please log in"
        ), 401

    # ── MAC verification ──
    if not verify_mac(cookie_payload, mac_tag):
        return render_template(
            "tampered.html",
            reason="HMAC tag does not match — cookie payload was modified"
        ), 403

    # ── Parse payload ──
    try:
        username, role, expiration = cookie_payload.split("|")
    except ValueError:
        return render_template("tampered.html", reason="malformed cookie structure"), 403

    # ── Expiry check ──
    if int(expiration) < int(time.time()):
        return render_template("tampered.html", reason="session has expired"), 403

    expiry_fmt = datetime.fromtimestamp(int(expiration)).strftime("%H:%M:%S")

    return render_template(
        "protected.html",
        username=username,
        role=role,
        expiry_fmt=expiry_fmt,
        raw_cookie=cookie_payload,
        raw_mac=mac_tag,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — Part B : Key generation
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/sign", methods=["GET"])
def sign_page():
    pub_pem = None
    if KEY_STORE["public_key"]:
        pub_pem = KEY_STORE["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="keygen",
    )


@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    """Generate a fresh RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    KEY_STORE["private_key"] = private_key
    KEY_STORE["public_key"]  = private_key.public_key()

    pub_pem = KEY_STORE["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="keygen",
        message="RSA-2048 key pair generated successfully.",
        msg_type="success",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — Part B : Sign & Verify
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/sign-file", methods=["POST"])
def sign_file():
    if not KEY_STORE["private_key"]:
        return render_template(
            "sign.html",
            public_key_pem=None,
            signed_files=list(SIGNED_FILES.keys()),
            active_tab="sign",
            message="Generate a key pair first.",
            msg_type="danger",
        )

    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template(
            "sign.html",
            public_key_pem=None,
            signed_files=list(SIGNED_FILES.keys()),
            active_tab="sign",
            message="No file selected.",
            msg_type="danger",
        )

    content = file.read()
    filename = file.filename

    # Sign using RSA-PKCS1v15 with SHA-256
    signature = KEY_STORE["private_key"].sign(
        content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    SIGNED_FILES[filename] = {
        "signature": signature,
        "content":   content,
    }

    pub_pem = KEY_STORE["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="sign",
        message=f"File '{filename}' signed successfully.",
        msg_type="success",
        signature_hex=signature.hex()[:128] + "...",
    )


@app.route("/verify-file", methods=["POST"])
def verify_file():
    filename   = request.form.get("filename")
    mode       = request.form.get("mode", "normal")
    verify_file_upload = request.files.get("verify_file")

    pub_pem = None
    if KEY_STORE["public_key"]:
        pub_pem = KEY_STORE["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    if not filename or filename not in SIGNED_FILES:
        return render_template(
            "sign.html",
            public_key_pem=pub_pem,
            signed_files=list(SIGNED_FILES.keys()),
            active_tab="verify",
            message="File not found in signed store.",
            msg_type="danger",
        )

    stored_sig = SIGNED_FILES[filename]["signature"]
    verify_content = verify_file_upload.read() if verify_file_upload else SIGNED_FILES[filename]["content"]

    try:
        KEY_STORE["public_key"].verify(
            stored_sig,
            verify_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        result = {
            "success":  True,
            "filename": filename,
            "message":  f"✓ Signature VALID — file '{filename}' is authentic and unmodified.",
        }
    except InvalidSignature:
        result = {
            "success":  False,
            "filename": filename,
            "message":  f"✕ Signature INVALID — file content has been modified after signing. Tampering detected!",
        }

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="verify",
        verify_result=result,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# BONUS — Attack Demonstrations (Wong, Page 150)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/attack/key-substitution", methods=["POST"])
def attack_key_substitution():
    """
    Key Substitution Attack:
    ─────────────────────────
    The attacker does NOT know the private key.
    Instead, they:
      1. Pick an arbitrary byte string as the "signature" s'
      2. Generate a fresh key pair (pk_attacker, sk_attacker)
      3. Sign the desired message m with sk_attacker → s_attacker
      4. Present (pk_attacker, m, s_attacker) to the verifier
    If the verifier only checks VERIFY(pk, m, sig) without binding pk
    to a trusted certificate/identity, verification passes.
    """
    message = request.form.get("message", "").encode()

    # Attacker generates their own key pair
    attacker_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    attacker_public = attacker_private.public_key()

    # Attacker signs the message with THEIR private key
    attacker_sig = attacker_private.sign(message, padding.PKCS1v15(), hashes.SHA256())

    # Verify passes because (pk_attacker, m, s_attacker) is internally consistent
    try:
        attacker_public.verify(attacker_sig, message, padding.PKCS1v15(), hashes.SHA256())
        verification_passes = True
    except InvalidSignature:
        verification_passes = False

    attacker_pub_pem = attacker_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    pub_pem = None
    if KEY_STORE["public_key"]:
        pub_pem = KEY_STORE["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    attack_result = {
        "attack_name": "Key Substitution Attack",
        "explanation": (
            "The attacker generated their OWN key pair and signed the forged message with it. "
            "Verification succeeds because (pk_attacker, m, sig_attacker) is internally consistent. "
            "Vulnerability: the verifier did not check that pk_attacker is the LEGITIMATE server key. "
            "Fix: bind public keys to identities via certificates (PKI/X.509)."
        ),
        "success": verification_passes,
        "details": {
            "Forged message":             message.decode(),
            "Attacker public key (PEM)":  attacker_pub_pem[:300] + "...",
            "Attacker signature (hex)":   attacker_sig.hex()[:128] + "...",
            "verify(pk_attacker, m, sig)": "PASSES ← vulnerability demonstrated" if verification_passes else "FAILS",
        }
    }

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="bonus",
        attack_result=attack_result,
    )


@app.route("/attack/msg-key-substitution", methods=["POST"])
def attack_msg_key_substitution():
    """
    Message/Key Substitution Attack (Wong p.150):
    ──────────────────────────────────────────────
    Given a valid (m, s) from the legitimate signer:
      1. Attacker picks a NEW message m' (malicious payload)
      2. Attacker generates a key pair (pk', sk') such that
         sign(sk', m') = s  [same signature byte string]
         This is hard in standard RSA, but Wong's scenario shows that
         if the verifier accepts ANY public key presented by the signer,
         the attacker can craft pk' so that VERIFY(pk', m', s) = True.
      3. Demonstration: attacker re-signs m' with sk' → s',
         then claims pk' is the legitimate key.

    We demonstrate this by showing that with an attacker-controlled key,
    a different message can be made to "verify" — exposing the trust model flaw.
    """
    filename = request.form.get("filename")

    if not filename or filename not in SIGNED_FILES:
        pub_pem = None
        if KEY_STORE["public_key"]:
            pub_pem = KEY_STORE["public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        return render_template(
            "sign.html",
            public_key_pem=pub_pem,
            signed_files=list(SIGNED_FILES.keys()),
            active_tab="bonus",
            message="Select a signed file first.",
            msg_type="danger",
        )

    original_content = SIGNED_FILES[filename]["content"]
    forged_message   = original_content + b"\n[TAMPERED BY ATTACKER - ADMIN ACCESS GRANTED]"

    # Attacker generates their key pair and signs the FORGED message
    attacker_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    attacker_public = attacker_private.public_key()
    attacker_sig = attacker_private.sign(forged_message, padding.PKCS1v15(), hashes.SHA256())

    # If verifier uses attacker's pk → verification passes on forged message
    try:
        attacker_public.verify(attacker_sig, forged_message, padding.PKCS1v15(), hashes.SHA256())
        attack_success = True
    except InvalidSignature:
        attack_success = False

    # Show that original sig fails on forged message (correct behavior)
    orig_sig = SIGNED_FILES[filename]["signature"]
    try:
        KEY_STORE["public_key"].verify(orig_sig, forged_message, padding.PKCS1v15(), hashes.SHA256())
        legit_verify = True
    except (InvalidSignature, Exception):
        legit_verify = False

    attacker_pub_pem = attacker_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    pub_pem = KEY_STORE["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode() if KEY_STORE["public_key"] else None

    attack_result = {
        "attack_name": "Message/Key Substitution Attack",
        "explanation": (
            "Given a valid (m, sig) pair, the attacker creates a FORGED message m' and a NEW key pair. "
            "They sign m' with their secret key → sig'. When the verifier is tricked into using pk_attacker "
            "instead of the legitimate pk, verify(pk_attacker, m', sig') PASSES. "
            "The original sig fails on m' with the legitimate key (correct). "
            "Vulnerability: no key authentication / certificate pinning. Fix: use PKI/X.509."
        ),
        "success": attack_success,
        "details": {
            "Original file":                  filename,
            "Forged message (tail)":          "[TAMPERED BY ATTACKER — ADMIN ACCESS GRANTED]",
            "Legitimate verify(pk, m', sig)": "FAILS ← correct" if not legit_verify else "PASSES",
            "Attack verify(pk', m', sig')":   "PASSES ← vulnerability" if attack_success else "FAILS",
            "Attacker public key (PEM)":      attacker_pub_pem[:300] + "...",
        }
    }

    return render_template(
        "sign.html",
        public_key_pem=pub_pem,
        signed_files=list(SIGNED_FILES.keys()),
        active_tab="bonus",
        attack_result=attack_result,
    )


# ─── 404 handler ──────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True, port=5000)


    
    #---------------------------------------------------------
