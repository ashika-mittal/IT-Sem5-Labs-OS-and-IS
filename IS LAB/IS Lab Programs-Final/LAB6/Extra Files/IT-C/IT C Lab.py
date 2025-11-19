from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import string
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

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

print("AES-128 IN CBC MODE")
key = os.urandom(16)  # AES-128 key

# Generate a random IV (16 bytes)
iv = os.urandom(16)

# Encryption
msg2=input("Enter Election Manifest: ")
msg = msg2.encode()
padded_msg = pad(msg, AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_msg)
print("Ciphertext (hex):", ciphertext.hex())
print("IV (hex):", iv.hex())

# Decryption (must use same IV!)
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = decipher.decrypt(ciphertext)
unpadded_msg = unpad(decrypted, AES.block_size)
print("Decrypted:", unpadded_msg.decode())

print("RSA Encryption of AES Key")

def rsa_encrypt(message: bytes, pub_key):
    """
    Encrypt a message using the public key.
    """
    ciphertext2 = pub_key.encrypt(
        message,
        padding.OAEP(  # OAEP padding is recommended
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext2

# ---------------------------
# RSA Decryption
# ---------------------------
def rsa_decrypt(ciphertext: bytes, priv_key):
    """
    Decrypt a message using the private key.
    """
    plaintext2 = priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext2

# ---------------------------
# Example usage
# ---------------------------
message = key

# Encrypt the message
encrypted_msg = rsa_encrypt(message, public_key)
print("\nEncrypted message (bytes):\n", encrypted_msg)

# Decrypt the message
decrypted_msg = rsa_decrypt(encrypted_msg, private_key)
print("\nDecrypted AES Key (hex):\n", decrypted_msg.hex())#NOTE THIS IN CASE OF ERROR


print("---SHA 256---")

# ---------------- Helper Function ----------------
def random_string(length=10):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def generate_dataset(size=None):
    dataset_size = size if size else random.randint(50, 100)
    return [random_string(random.randint(8, 16)) for _ in range(dataset_size)]

# ---------------- SHA-256 Hashing ----------------
def hash_sha256(dataset):
    hashes = {}
    collisions = []
    start_time = time.time()

    print("\n=== SHA-256 Hashing ===")
    for s in dataset:
        h = hashlib.sha256(s.encode()).hexdigest()  # <-- HASH GENERATED
        print(f"{s} -> {h}")                        # <-- PRINT HASH
        if h in hashes and hashes[h] != s:
            collisions.append((hashes[h], s))
        else:
            hashes[h] = s

    end_time = time.time()
    print(f"\nDataset size: {len(dataset)} random strings")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print(f"Collisions detected: {len(collisions)}")
    if collisions:
        print("Collision pairs:")
        for c in collisions:
            print(f"  {c[0]} <--> {c[1]}")


# ---------------- Main ----------------
if __name__ == "__main__":
    dataset = generate_dataset()

    # Call whichever hashing function you want
    hash_sha256(msg2)

print("--DIGITAL SIGNATURE---")
# ---------------- Step 1: Generate RSA Keys ----------------
def generate_rsa_keys():
    private_key3 = rsa.generate_private_key(
        public_exponent=65537,  # same as 0x10001
        key_size=2048
    )
    public_key3 = private_key.public_key()
    return private_key3, public_key3


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
    alice_private = private_key
    alice_public = public_key

    # Alice signs her document
    # The 'document' can be any content we choose — it could be a legal document, a message, or even just a name.
    document = b"Legal Document: Agreement between Alice and Bob"
    alice_signature = sign_document(alice_private, document)
    print("CANDIDATE X SIGNATURE:", alice_signature.hex())

    # Bob verifies Alice's signature
    verified = verify_signature(alice_public, document, alice_signature)
    print("ELECTION COMMISSION VERIFICATION:", "✅ Verified" if verified else "❌ Failed")

    # Bob creates his own signature
    bob_private, bob_public = generate_rsa_keys()
    bob_document = b"Response Document: Acknowledged by Bob"
    bob_signature = sign_document(bob_private, bob_document)
    print("ELECTION COMMISSION SIGNATURE:", bob_signature.hex())

    # Alice verifies Bob's signature
    verified_bob = verify_signature(bob_public, bob_document, bob_signature)
    print("CANDIDATE X verifies ELECTION COMMISSION'S signature:", "✅ Verified" if verified_bob else "❌ Failed")







