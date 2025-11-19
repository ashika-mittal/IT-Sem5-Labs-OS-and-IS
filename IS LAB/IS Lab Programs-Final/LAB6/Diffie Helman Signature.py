from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------- Step 1: Generate DH parameters (fast demo version) ----------------
parameters = dh.generate_parameters(generator=2, key_size=512)  # 512-bit for quick demo

# ---------------- Step 2: Alice & Bob generate private/public keys ----------------
alice_private_key = parameters.generate_private_key()
bob_private_key = parameters.generate_private_key()

alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

# ---------------- Step 3: Exchange keys and derive shared secret ----------------
alice_shared_key = alice_private_key.exchange(bob_public_key)
bob_shared_key = bob_private_key.exchange(alice_public_key)

# Both should be equal
assert alice_shared_key == bob_shared_key

# ---------------- Step 4: Derive a symmetric key from shared secret ----------------
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data"
).derive(alice_shared_key)

# ---------------- Step 5: Alice “signs” a document using HMAC ----------------
document = b"Legal Document: Agreement between Alice and Bob"
h = hmac.HMAC(derived_key, hashes.SHA256())
h.update(document)
alice_hmac = h.finalize()
print("Alice's HMAC (acts like signature):", alice_hmac.hex())

# ---------------- Step 6: Bob verifies Alice's HMAC ----------------
h2 = hmac.HMAC(derived_key, hashes.SHA256())
h2.update(document)
try:
    h2.verify(alice_hmac)
    print("Bob verifies Alice's message integrity and authenticity ✅")
except:
    print("Verification failed ❌")

# ---------------- Step 7: Bob “signs” his response ----------------
bob_document = b"Response Document: Acknowledged by Bob"
h3 = hmac.HMAC(derived_key, hashes.SHA256())
h3.update(bob_document)
bob_hmac = h3.finalize()
print("Bob's HMAC (acts like signature):", bob_hmac.hex())

# ---------------- Step 8: Alice verifies Bob's HMAC ----------------
h4 = hmac.HMAC(derived_key, hashes.SHA256())
h4.update(bob_document)
try:
    h4.verify(bob_hmac)
    print("Alice verifies Bob's message integrity and authenticity ✅")
except:
    print("Verification failed ❌")
# Diffie-Hellman is only used for key exchange to generate a shared secret.
# It does not encrypt messages or sign documents. HMAC uses the shared key
# to ensure message integrity and authenticity, simulating a digital signature.

