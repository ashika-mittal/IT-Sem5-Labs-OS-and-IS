from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

message = b"My legal contract agreement"

# Hash the message (SHA-256)
hasher = hashes.Hash(hashes.SHA256())
hasher.update(message)
msg_hash = hasher.finalize()

# Sign the hash with private key
signature = private_key.sign(
    msg_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verification (receiver side)
try:
    public_key.verify(
        signature,
        msg_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature valid. Document is authentic.")
except Exception:
    print("Signature verification failed!")
