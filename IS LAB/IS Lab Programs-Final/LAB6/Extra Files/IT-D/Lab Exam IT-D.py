from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import hashlib
import string
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import math
from Crypto.Util.number import getPrime


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


# Helper functions
def text_to_nums(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)

def mod_inverse(a, m):
    return inverse(a,m)


# Encrypt the message
def encrypt(message, q, h, g):
    k = random.randint(1, q-2)  # Sender's ephemeral key
    s = pow(h, k, q)  # Shared secret
    p = pow(g, k, q)  # Cipher component
    encrypted = [s * ord(char) for char in message]
    print("g^k used:", p)
    print("h^k used:", s)
    return encrypted, p

# Decrypt the message
def decrypt(encrypted, p, x, q):
    s = pow(p, x, q)  # Shared secret
    decrypted = [chr(int(c // s)) for c in encrypted]
    return ''.join(decrypted)


# ---------- c) Affine Cipher ----------
def affine_encrypt(plaintext, a, b):
    nums = text_to_nums(plaintext)
    enc = [(a * x + b) % 26 for x in nums]
    return nums_to_text(enc)

def affine_decrypt(ciphertext, a, b):
    inv_a = mod_inverse(a, 26)
    nums = text_to_nums(ciphertext)
    dec = [((x - b) * inv_a) % 26 for x in nums]
    return nums_to_text(dec)


# ----------------- Test -----------------
msg = "PATIENTSUGAR120"

# c) Affine
aff_enc = affine_encrypt(msg, 7, 9)
aff_dec = affine_decrypt(aff_enc, 7, 9)
print("Affine:", aff_enc, "->", aff_dec)


key=bytes.fromhex("1234567890ABCDEF1234567890ABCDEF")
msg = aff_enc.encode()
padded_msg=pad(msg,AES.block_size)
cipher=AES.new(key,AES.MODE_ECB)
ciphertext=cipher.encrypt(padded_msg)
print("The encrypted ciphertext with AES  ",ciphertext.hex())

decrypt2=cipher.decrypt(ciphertext)
unpadded_msg=unpad(decrypt2,AES.block_size)
print("The decrypted ciphertext with AES  ",unpadded_msg.decode())

print("ELGAMAL ENCRYPTION FOR AES KEY")
# Main flow
message = "1234567890ABCDEF1234567890ABCDEF"
print("Original Message:", message)

q = getPrime(256)  # Generates a 256-bit prime number
g = random.randint(2, q)            # Generator
x = random.randint(1,q-2)           # Receiver's private key
h = pow(g, x, q)                    # Receiver's public key

print("g used:", g)
print("h = g^x mod q:", h)

encrypted_msg, p = encrypt(message, q, h, g)
decrypted_msg = decrypt(encrypted_msg, p, x, q)

print("Decrypted Message:", decrypted_msg)


print("HASH FUNCTION IMPLEMENTATION")


def custom_hash(s: str) -> int:
    hash_val = 5381  # Initial hash value

    for ch in s:
        # Multiply by 33 and add ASCII of character
        hash_val = ((hash_val << 5) + hash_val) + ord(ch)

        # Keep it within 32-bit range
        hash_val &= 0xFFFFFFFF

    return hash_val


# Example usage
if __name__ == "__main__":

    text= input("Enter the text: ")
    print(f"Hash of '{text}' = {custom_hash(text)}")


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

    for s in dataset:
        h = hashlib.sha256(s.encode()).hexdigest()
        if h in hashes and hashes[h] != s:
            collisions.append((hashes[h], s))
        else:
            hashes[h] = s

    end_time = time.time()
    print("\n=== SHA-256 Hashing ===")
    print(f"Dataset size: {len(dataset)} random strings")
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
    hash_sha256(dataset)


print("DIGITAL SIGNATURE IMPLEMENTATION")


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

if __name__ == "__main__":
    # Alice generates keys
    alice_private, alice_public = generate_rsa_keys()

    # Alice signs her document
    # The 'document' can be any content we choose — it could be a legal document, a message, or even just a name.
    text= input("Enter the text: ")
    document = text.encode()
    alice_signature = sign_document(alice_private, document)
    print("HOSPITAL'S SIGN:", alice_signature.hex())

    # Bob verifies Alice's signature
    verified = verify_signature(alice_public, document, alice_signature)
    print("VERIFICATION OF HOSPITAL SIGN:", "✅ Verified" if verified else "❌ Failed")

    # Bob creates his own signature
    bob_private, bob_public = generate_rsa_keys()
    bob_document = b"Response Document: Acknowledged by Bob"
    bob_signature = sign_document(bob_private, bob_document)
    print("Receiver's Signature:", bob_signature.hex())

    # Alice verifies Bob's signature
    verified_bob = verify_signature(bob_public, bob_document, bob_signature)
    print("HOSPITAL SIGN VERIFICATION:", "✅ Verified" if verified_bob else "❌ Failed")

    tampered_doc2= input("Enter tampered text: ")
    tampered_doc=tampered_doc2.encode()
    verified_tampered = verify_signature(alice_public, tampered_doc, alice_signature)
    print("VERIFICATION AFTER TAMPERING:", "✅ Verified" if verified_tampered else "❌ Failed")







