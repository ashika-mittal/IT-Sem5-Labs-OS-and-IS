from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Key Generation for Alice
alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
alice_public_key = alice_private_key.public_key()

# Key Generation for Bob
bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_public_key = bob_private_key.public_key()

# Plaintext message
message = b"Lab 6 additional exercise demo"

# 1. Confidentiality: Encrypt the message using Bob's public key
ciphertext = bob_public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 2. Integrity: Hash the ciphertext using SHA-256
digest = hashes.Hash(hashes.SHA256())
digest.update(ciphertext)
hashed_ciphertext = digest.finalize()

# 3. Authenticity: Alice signs the hashed ciphertext using her private key
signature = alice_private_key.sign(
    hashed_ciphertext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Bob receives ciphertext, hashed_ciphertext, Alice's signature, and Alice's public key

# Bob verifies the signature first for authenticity and integrity
try:
    alice_public_key.verify(
        signature,
        hashed_ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verified: Authentic and Integrity guaranteed.")
    # Decrypt ciphertext for confidentiality
    decrypted_message = bob_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Decrypted message:", decrypted_message.decode())
except Exception:
    print("Signature verification failed or message tampered.")

