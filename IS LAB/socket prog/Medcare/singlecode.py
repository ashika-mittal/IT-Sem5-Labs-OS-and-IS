"""
MedCare System (educational skeleton)

Structure:
 1. Key generation and helper functions
 2. Cryptographic primitives (placeholders for ElGamal, Paillier, SHA256)
 3. Tampering-detection function
 4. Server + Client simulation in one file
"""

# ------------------------------------------------------------
# 1. Imports and key helpers
# ------------------------------------------------------------
import socket, pickle, hashlib, random
from Crypto.Util.number import getPrime, inverse

# ------------------------------------------------------------
# 2. Cryptographic placeholders
# ------------------------------------------------------------

# ---------- ElGamal ----------
def elgamal_generate_keys(bits=256):
    # TODO: paste your working ElGamal key-generation function
    p = getPrime(bits)
    g = random.randint(2, p - 1)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(msg_hash_int, priv_x, p, g):
    # TODO: your signing logic here
    return (r, s)

def elgamal_verify(p, g, y, msg_hash_int, r, s):
    # TODO: your verification logic here
    return True

# ---------- Paillier ----------
def paillier_generate_keys(bits=256):
    # TODO: paste your Paillier keypair generation
    p = getPrime(bits); q = getPrime(bits)
    n = p*q; g = n+1
    lam = (p-1)*(q-1)
    mu = inverse(lam, n)
    return (n, g), (lam, mu, n)

def paillier_encrypt(m, pub):
    n, g = pub
    r = random.randint(1, n-1)
    return pow(g, m, n*n) * pow(r, n, n*n) % (n*n)

def paillier_decrypt(c, priv):
    lam, mu, n = priv
    x = pow(c, lam, n*n)
    l = (x-1)//n
    return (l*mu) % n

# ---------- SHA-256 ----------
def sha256_hash(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

# ------------------------------------------------------------
# 3. Tampering detection
# ------------------------------------------------------------
def detect_tampering(hashes):
    seen = set()
    for h in hashes:
        if h in seen:
            return "⚠️ Data Tampered (Duplicate hash found)"
        seen.add(h)
    return "✅ Data Safe (All hashes unique)"

# ------------------------------------------------------------
# 4. Combined workflow (local simulation or socket ready)
# ------------------------------------------------------------
def medcare_simulation():
    print("🏥  MedCare Secure-Aggregation Demo\n")

    # --- Key setup ---
    elg_pub, elg_priv = elgamal_generate_keys()
    pai_pub, pai_priv = paillier_generate_keys()

    # --- Hospitals send encrypted + signed + hashed data ---
    hospital_data = [15, 25]
    enc_values, hashes = [], []

    for idx, val in enumerate(hospital_data, 1):
        h = sha256_hash(val)
        hashes.append(h)
        c = paillier_encrypt(val, pai_pub)
        enc_values.append(c)
        print(f"Hospital-{idx}: val={val}, hash={h[:10]}..., ciphertext={str(c)[:10]}...")

    # --- Tampering check ---
    print("\nIntegrity:", detect_tampering(hashes))

    # --- Homomorphic addition ---
    n, g = pai_pub
    combined_enc = 1
    for c in enc_values:
        combined_enc = (combined_enc * c) % (n*n)

    decrypted_sum = paillier_decrypt(combined_enc, pai_priv)
    print(f"Decrypted aggregate = {decrypted_sum} (expected {sum(hospital_data)})")

    print("\n✅  Simulation complete.\n")

# ------------------------------------------------------------
# 5. Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    medcare_simulation()
