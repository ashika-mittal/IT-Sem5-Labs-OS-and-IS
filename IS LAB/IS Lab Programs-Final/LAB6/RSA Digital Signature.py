from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ---------------- Step 1: Generate RSA Keys ----------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # same as 0x10001
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ---------------- Step 2: Sign a Document ----------------
def sign_document(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# ---------------- Step 3: Verify a Signature ----------------
def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# ---------------- Demo ----------------
if __name__ == "__main__":
    # Alice generates keys
    alice_private, alice_public = generate_rsa_keys()

    # Alice signs her document
    # The 'document' can be any content we choose — it could be a legal document, a message, or even just a name.
    document = b"Legal Document: Agreement between Alice and Bob"
    alice_signature = sign_document(alice_private, document)
    print("Alice's Signature:", alice_signature.hex())

    # Bob verifies Alice's signature
    verified = verify_signature(alice_public, document, alice_signature)
    print("Bob verifies Alice's signature:", "✅ Verified" if verified else "❌ Failed")

    # Bob creates his own signature
    bob_private, bob_public = generate_rsa_keys()
    bob_document = b"Response Document: Acknowledged by Bob"
    bob_signature = sign_document(bob_private, bob_document)
    print("Bob's Signature:", bob_signature.hex())

    # Alice verifies Bob's signature
    verified_bob = verify_signature(bob_public, bob_document, bob_signature)
    print("Alice verifies Bob's signature:", "✅ Verified" if verified_bob else "❌ Failed")

    tampered_doc2 = input("Enter tampered text: ")
    tampered_doc = tampered_doc2.encode()
    verified_tampered = verify_signature(alice_public, tampered_doc, alice_signature)
    print("VERIFICATION AFTER TAMPERING:", "✅ Verified" if verified_tampered else "❌ Failed")
  #WHEREVER CONDITIONAL GIVEN THAT A SIGN SHOULD FAIL IF XYZ TEXT ENTERED USE THIS

# NOTE:
# The verification will fail here because the signature was created
# for the original message ("Patient Sugar").
# When we try to verify it against the tampered message ("Patient Pressure"),
# the hash of the new message is completely different.
# Since digital signatures bind the signature to the exact message content,
# even a small change makes the signature invalid.
