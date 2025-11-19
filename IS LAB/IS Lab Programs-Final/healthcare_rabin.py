#BASIC SHA RABIN ELGAMAL
import hashlib
import random, math
from random import randint
import time

# ---------- SHA-512 Hash ----------
def sha512_hash(message: str) -> str:
    """Return hex SHA-512 digest of a string."""
    return hashlib.sha512(message.encode()).hexdigest()

# ---------- Rabin Cryptosystem ----------
def rabin_keygen(bits=512):
    """Generate Rabin keys: n = p*q, p ≡ q ≡ 3 mod 4."""
    def prime_3mod4():
        while True:
            p = random.getrandbits(bits // 2)
            if p % 4 == 3 and pow(2, p - 1, p) == 1:
                return p
    p, q = prime_3mod4(), prime_3mod4()
    return (p, q, p * q)      # private: (p,q), public: n

def rabin_encrypt(message: str, n: int) -> int:
    m = int.from_bytes(message.encode(), 'big')
    return pow(m, 2, n)

def rabin_decrypt(cipher: int, p: int, q: int) -> str:
    # Chinese Remainder to find square roots
    mp = pow(cipher, (p + 1) // 4, p)
    mq = pow(cipher, (q + 1) // 4, q)
    # combine
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    r1 = (yp * p * mq + yq * q * mp) % (p * q)
    r2 = (p * q - r1) % (p * q)
    r3 = (yp * p * (-mq) + yq * q * mp) % (p * q)
    r4 = (p * q - r3) % (p * q)
    for r in [r1, r2, r3, r4]:
        try:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big').decode()
        except UnicodeDecodeError:
            continue
    raise ValueError("No valid plaintext root")

# ---------- ElGamal Digital Signature ----------
def elgamal_keygen(p: int, g: int):
    """Generate ElGamal keys given prime p and generator g."""
    x = randint(1, p - 2)          # private
    y = pow(g, x, p)               # public
    return (p, g, y, x)

def elgamal_sign(message: str, p: int, g: int, x: int) -> tuple:
    """Sign SHA-512 hash of message."""
    h = int(sha512_hash(message), 16)
    while True:
        k = randint(1, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * pow(k, -1, p - 1)) % (p - 1)
    return (r, s)

def elgamal_verify(message: str, sig: tuple, p: int, g: int, y: int) -> bool:
    """Verify ElGamal signature (r,s)."""
    r, s = sig
    if not (0 < r < p):
        return False
    h = int(sha512_hash(message), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

# ---------- Auditor Log ----------
audit_log = []

def record_transaction(customer: str, merchant: str, hash_val: str, signature: tuple):
    """Append a transaction record for auditor."""
    audit_log.append({
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer': customer,
        'merchant': merchant,
        'hash': hash_val,
        'signature': signature
    })

# ---------- Main Menu ----------
def main_menu():
    # Rabin keys
    p_rabin, q_rabin, n_rabin = rabin_keygen(512)
    # ElGamal keys (for demo we pick a small safe prime; replace with bigger if needed)
    p_elg = 30803
    g_elg = 2
    p, g, y, x = elgamal_keygen(p_elg, g_elg)

    customer_name = "Customer1"
    merchant_name = "Merchant1"

    encrypted_msg = None
    signature = None
    original_msg = None
    hash_msg = None

    while True:
        print("\n==== Finsecure Corp Menu ====")
        print("1. Customer: Encrypt + Hash + Sign")
        print("2. Merchant: Verify + Decrypt")
        print("3. Auditor: View Transaction Log")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            msg = input("Enter transaction message: ")
            original_msg = msg
            encrypted_msg = rabin_encrypt(msg, n_rabin)
            hash_msg = sha512_hash(msg)
            signature = elgamal_sign(msg, p, g, x)
            record_transaction(customer_name, merchant_name, hash_msg, signature)
            print("\n[Customer] Message encrypted & signed.")
            print("Ciphertext:", encrypted_msg)
            print("SHA512 Hash:", hash_msg)
            print("Signature (r,s):", signature)

        elif choice == "2":
            if not encrypted_msg:
                print("\n[Merchant] No message to verify/decrypt yet.")
                continue
            if elgamal_verify(original_msg, signature, p, g, y):
                print("\n[Merchant] Signature verified.")
                decrypted = rabin_decrypt(encrypted_msg, p_rabin, q_rabin)
                print("Decrypted Message:", decrypted)
            else:
                print("\n[Merchant] Signature verification failed!")

        elif choice == "3":
            print("\n[Auditor] Transaction Records:")
            for rec in audit_log:
                print(f"Time: {rec['time']}, Customer: {rec['customer']}, "
                      f"Merchant: {rec['merchant']}\n  Hash: {rec['hash']}\n  Signature: {rec['signature']}\n")

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid option, try again.")

#if name == "_main_":
main_menu()