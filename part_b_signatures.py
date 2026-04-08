"""
Part B: Digital Signature System
=================================
1. Generate RSA key pair
2. Sign a file
3. Verify the file (pass & fail cases)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ───────────────────────────────────────────────
# STEP 1: Generate RSA Key Pair
# ───────────────────────────────────────────────
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[1] Key pair generated → private_key.pem, public_key.pem")

# ───────────────────────────────────────────────
# STEP 2: Sign a File
# ───────────────────────────────────────────────
def sign_file(filename):
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(filename, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as f:
        f.write(signature)

    print(f"[2] File '{filename}' signed → signature.sig")

# ───────────────────────────────────────────────
# STEP 3: Verify a File
# ───────────────────────────────────────────────
def verify_file(filename):
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open("signature.sig", "rb") as f:
        signature = f.read()

    with open(filename, "rb") as f:
        data = f.read()

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
        print(f"[3] Verification SUCCESS ✓ — '{filename}' is authentic and unmodified")
    except InvalidSignature:
        print(f"[3] Verification FAILED ✗ — '{filename}' has been tampered with!")

# ───────────────────────────────────────────────
# DEMO: Run all steps
# ───────────────────────────────────────────────
if __name__ == "__main__":

    # Create a sample file to sign
    with open("document.txt", "w") as f:
        f.write("This is the original document. Do not modify.")

    print("=" * 50)
    print("        Part B: Digital Signature Demo")
    print("=" * 50)

    # Step 1
    generate_keys()

    # Step 2
    sign_file("document.txt")

    # Step 3a: Verify original → should PASS
    print("\n--- Test 1: Original file ---")
    verify_file("document.txt")

    # Step 3b: Tamper the file, verify → should FAIL
    print("\n--- Test 2: Tampered file ---")
    with open("document.txt", "a") as f:
        f.write("\n[TAMPERED]")
    verify_file("document.txt")

    print("=" * 50)