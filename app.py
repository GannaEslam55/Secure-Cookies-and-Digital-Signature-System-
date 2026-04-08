import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

print("Current Working Directory:", os.getcwd())

# =========================
# FILE PATHS
# =========================
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


# =========================
# KEY GENERATION
# =========================
def generate_keys(force_new=False):
    if force_new:
        print("[!] Forcing new key generation...")
        if os.path.exists(PRIVATE_KEY_FILE):
            os.remove(PRIVATE_KEY_FILE)
        if os.path.exists(PUBLIC_KEY_FILE):
            os.remove(PUBLIC_KEY_FILE)

    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        print("[+] Using existing keys.")
        return

    print("[+] Generating NEW RSA key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    fingerprint = hashlib.sha256(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()

    print("[+] Keys generated successfully.")
    print("[+] Public Key Fingerprint:", fingerprint)
    print("[+] Timestamp:", datetime.now())


# =========================
# LOAD KEYS
# =========================
def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# =========================
# SIGN FILE
# =========================
def sign_file(file_path):
    if not os.path.exists(file_path):
        print("[!] File does not exist.")
        return

    private_key = load_private_key()

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_file = file_path + ".sig"

    with open(sig_file, "wb") as f:
        f.write(signature)

    print(f"[+] File signed successfully → {sig_file}")


# =========================
# VERIFY SIGNATURE
# =========================
def verify_signature(file_path):
    sig_file = file_path + ".sig"

    if not os.path.exists(file_path) or not os.path.exists(sig_file):
        print("[!] Missing file or signature.")
        return

    public_key = load_public_key()

    with open(file_path, "rb") as f:
        data = f.read()

    with open(sig_file, "rb") as f:
        signature = f.read()

    print("[INFO] Using public key from:", PUBLIC_KEY_FILE)
    print("[INFO] Signature file:", sig_file)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[+] Signature VALID (file is authentic).")

    except Exception:
        print("[!] Signature INVALID (file modified OR key changed).")


# =========================
# ATTACK 1: Key Substitution
# =========================
def key_substitution_attack(file_path):
    print("\n[ATTACK] Key Substitution Attack")

    if not os.path.exists(file_path):
        print("[!] File does not exist.")
        return

    attacker_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    attacker_public = attacker_private.public_key()

    with open(file_path, "rb") as f:
        data = f.read()

    fake_signature = attacker_private.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("[+] Attacker replaced the legitimate key with his own.")

    try:
        attacker_public.verify(
            fake_signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[!!!] Verification PASSED (but WRONG — key was substituted!)")

    except Exception:
        print("[OK] Verification failed")


# =========================
# ATTACK 2: Message-Key Substitution
# =========================
def message_key_substitution_attack():
    print("\n[ATTACK] Message-Key Substitution Attack")

    fake_message = b"This is a FAKE message"

    attacker_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    attacker_public = attacker_private.public_key()

    fake_signature = attacker_private.sign(
        fake_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    try:
        attacker_public.verify(
            fake_signature,
            fake_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[!!!] Verification PASSED on fake message (WRONG DESIGN!)")

    except Exception:
        print("[OK] Verification failed")


# =========================
# MENU
# =========================
def menu():
    while True:
        print("\n===== DIGITAL SIGNATURE SYSTEM =====")
        print("1. Generate Keys (first time)")
        print("2. Generate NEW Keys (force)")
        print("3. Sign File")
        print("4. Verify Signature")
        print("5. Key Substitution Attack")
        print("6. Message-Key Substitution Attack")
        print("7. Exit")

        choice = input("Choose: ")

        if choice == "1":
            generate_keys()

        elif choice == "2":
            generate_keys(force_new=True)

        elif choice == "3":
            file_path = input("Enter file name: ")
            sign_file(file_path)

        elif choice == "4":
            file_path = input("Enter file name: ")
            verify_signature(file_path)

        elif choice == "5":
            file_path = input("Enter file name: ")
            key_substitution_attack(file_path)

        elif choice == "6":
            message_key_substitution_attack()

        elif choice == "7":
            break

        else:
            print("[!] Invalid choice.")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    menu()