"""
Demonstration of secure data encryption, transmission, and digital signatures
using GnuPG-like concepts implemented purely in Python.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64

# --- Helper functions ---

def generate_rsa_keys():
    """Generate RSA key pair (like GnuPG key generation)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(public_key, data):
    """Encrypt data with AES + RSA (like GnuPG hybrid encryption)."""
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(iv + enc_key + ciphertext).decode()

def decrypt_data(private_key, enc_message):
    """Decrypt data with RSA + AES (reverse of above)."""
    data = base64.b64decode(enc_message)
    iv, enc_key, ciphertext = data[:16], data[16:16+256], data[16+256:]

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def sign_data(hmac_key, data):
    """Create digital signature using HMAC (simulating GnuPG signing)."""
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data.encode())
    return base64.b64encode(h.finalize()).decode()

def verify_signature(hmac_key, data, signature):
    """Verify signature to ensure integrity/authenticity."""
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data.encode())
    try:
        h.verify(base64.b64decode(signature))
        return True
    except Exception:
        return False

# --- Demonstration ---
def demo():
    print("\n🔐 Simulating Secure Communication using GnuPG concepts in Python")

    # Generate sender/receiver RSA key pairs
    sender_priv, sender_pub = generate_rsa_keys()
    receiver_priv, receiver_pub = generate_rsa_keys()

    # Generate separate key for digital signatures (like passphrase-based signing key)
    hmac_key = os.urandom(32)

    message = "Confidential: Project data for transmission."
    print("\nOriginal Message:", message)

    # Encryption (like 'gpg --encrypt')
    encrypted = encrypt_data(receiver_pub, message)
    print("\nEncrypted Message:", encrypted[:80] + "...")

    # Decryption (like 'gpg --decrypt')
    decrypted = decrypt_data(receiver_priv, encrypted)
    print("\nDecrypted Message:", decrypted)

    # Signing (like 'gpg --sign')
    signature = sign_data(hmac_key, message)
    print("\nDigital Signature:", signature)

    # Verification (like 'gpg --verify')
    valid = verify_signature(hmac_key, message, signature)
    print("\n✅ Signature valid =", valid)

if __name__ == "__main__":
    demo()
