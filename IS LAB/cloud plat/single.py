import hashlib
from Crypto.Util.number import getPrime, inverse
import re
def canon(s: str) -> str:
    # use the same canonical form everywhere
    return re.sub(r'[^A-Za-z]', '', s).lower()

# ---------- Step 1: Hash ----------
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ---------- Step 2: Affine Cipher ----------
def gcd(a, b):
    while b: a, b = b, a % b
    return a

def mod_inverse(a, m):
    for x in range(1, m):
        if (a*x) % m == 1:
            return x
    return None

def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")
    return ''.join(chr(((a*(ord(ch)-97)+b)%26)+97) for ch in text.lower() if ch.isalpha())

def affine_decrypt(cipher, a, b):
    a_inv = mod_inverse(a, 26)
    return ''.join(chr(((a_inv*((ord(ch)-97)-b))%26)+97) for ch in cipher.lower() if ch.isalpha())

# ---------- Step 3: RSA Digital Signature ----------
def rsa_keygen(bits=512):
    p, q = getPrime(bits//2), getPrime(bits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = inverse(e, phi)
    return (n, e), (n, d)

def rsa_sign(msg, priv):
    n, d = priv
    h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big')
    return pow(h, d, n)

def rsa_verify(msg, sig, pub):
    n, e = pub
    h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), 'big') % n
    return pow(sig, e, n) == h

# ---------- Step 4: Simulated Cloud DB ----------
records = []
a, b = 7, 3  # affine keys
pub, priv = rsa_keygen()

# def add_record(name, disease, treatment):
#     record = f"{name}-{disease}-{treatment}"
#     hash_val = sha256_hash(record)
#     enc_record = affine_encrypt(record, a, b)
#     signature = rsa_sign(record, priv)
#     records.append({"cipher": enc_record, "hash": hash_val, "sig": signature})
#     print("\nRecord added successfully!")
#     print("Hash:", hash_val)
#     print("Encrypted record:", enc_record)
#     print("Digital Signature:", signature)

def add_record(name, disease, treatment):
    plain_raw   = f"{name}-{disease}-{treatment}"
    plain_canon = canon(plain_raw)

    # 1) Hash the CANON string
    hash_val = hashlib.sha256(plain_canon.encode()).hexdigest()

    # 2) Encrypt the CANON string (Affine)
    enc_record = affine_encrypt(plain_canon, a, b)

    # 3) Sign the CANON string (RSA)
    signature = rsa_sign(plain_canon, priv)

    records.append({
        "cipher": enc_record,
        "hash": hash_val,
        "sig": signature,
        # (optional) store what you signed, for auditing/debug
        "signed_plain": plain_canon
    })
    print("\nRecord added successfully!")
    print("Hash:", hash_val)
    print("Encrypted record:", enc_record)
    print("Digital Signature:", signature)

def search_record(keyword):
    enc_keyword = affine_encrypt(keyword, a, b)
    print(f"\nSearching for keyword '{keyword}' (encrypted as '{enc_keyword}')...")
    for r in records:
        if enc_keyword in r["cipher"]:
            dec = affine_decrypt(r["cipher"], a, b)
            print("✅ Record found and decrypted:", dec)
            ok = rsa_verify(dec, r["sig"], pub)
            print("Signature verification:", "✅ Valid" if ok else "❌ Invalid")
            return
    print("No matching record found.")

# ---------- Demo ----------
add_record("Riya", "Malaria", "Paracetamol")
add_record("Amit", "Covid", "Remdesivir")

search_record("Covid")