from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ---------------------------
# RSA Key Generation
# ---------------------------

# Generate RSA private key
# To change key size (e.g., 3072 or 4096 bits), modify key_size below
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048  # <-- Change this number to generate a different bit-size key
)
# Even if the public key PEM looks shorter, it still represents a 2048-bit key
# Extract the corresponding public key
public_key = private_key.public_key()

# ---------------------------
# Export keys to PEM format (optional)
# ---------------------------
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # No password protection
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:\n", pem_private.decode())
print("Public Key:\n", pem_public.decode())

# ---------------------------
# RSA Encryption
# ---------------------------
def rsa_encrypt(message: bytes, pub_key):
    """
    Encrypt a message using the public key.
    """
    ciphertext = pub_key.encrypt(
        message,
        padding.OAEP(  # OAEP padding is recommended
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# ---------------------------
# RSA Decryption
# ---------------------------
def rsa_decrypt(ciphertext: bytes, priv_key):
    """
    Decrypt a message using the private key.
    """
    plaintext = priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# ---------------------------
# Example usage
# ---------------------------
message = b"Hello, this is a secret message!"

# Encrypt the message
encrypted_msg = rsa_encrypt(message, public_key)
print("\nEncrypted message (bytes):\n", encrypted_msg)

# Decrypt the message
decrypted_msg = rsa_decrypt(encrypted_msg, private_key)
print("\nDecrypted message:\n", decrypted_msg.decode())
