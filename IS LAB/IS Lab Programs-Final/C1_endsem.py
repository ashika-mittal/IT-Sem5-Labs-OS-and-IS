import hashlib
import random
from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# ===============================
# --- SIMPLE PAILLIER IMPLEMENTATION ---
# ===============================

def lcm(x, y):
    return x * y // gcd(x, y)

def generate_paillier_keys(bit_length=256):
    p = 137 #int(input("Enter p :"))
    q = 131 #int(input("Enter q :"))
    n = p * q
    lam = lcm(p - 1, q - 1)
    g = n + 1
    mu = pow(lam, -1, n)
    print(f"Paillier Key Generation:\n  p={p}, q={q}, n={n}\n  λ(lcm)={lam}, g={g}, μ={mu}\n")
    return (n, g), (lam, mu)

def paillier_encrypt(pub_key, m):
    n, g = pub_key
    r = random.randint(1, n - 1)
    c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
    print(f"Paillier Encryption:\n  Message m={m}\n  Random r={r}\n  Ciphertext c={c}\n")
    return c

def paillier_decrypt(priv_key, pub_key, c):
    n, g = pub_key
    lam, mu = priv_key
    x = pow(c, lam, n * n)
    L = (x - 1) // n
    decrypted = (L * mu) % n
    print(f"Paillier Decryption:\n  Ciphertext c={c}\n  x={x}\n  L(x)={(x - 1) // n}\n  Decrypted m={decrypted}\n")
    return decrypted

def paillier_add(pub_key, c1, c2):
    n, g = pub_key
    c_sum = (c1 * c2) % (n * n)
    print(f"Homomorphic Addition:\n  c1={c1}\n  c2={c2}\n  c_sum (c1*c2 mod n^2)={c_sum}\n")
    return c_sum

# ===============================
# --- CLIENT SIDE ---
# ===============================

def sha256_hash(data):
    h = hashlib.sha256(data.encode()).hexdigest()
    print(f"SHA-256 Hash of '{data}' = {h}")
    return h

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print("\nRSA Key Pair generated successfully.\n")
    return private_key, private_key.public_key()

def sign_data(private_key, data_hash):
    sig = private_key.sign(
        data_hash.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print(f"RSA Signature generated for hash {data_hash[:10]}... = {sig.hex()[:50]}...\n")
    return sig

def client_send_data():
    hospitals = int(input("Enter number of hospitals: "))
    data_list = []

    rsa_priv, rsa_pub = generate_rsa_keys()
    paillier_pub, paillier_priv = generate_paillier_keys()

    for i in range(hospitals):
        value = int(input(f"Enter numeric data from Hospital {i+1}: "))
        print(f"\n--- Processing Hospital {i+1} ---")
        h = sha256_hash(str(value))
        sig = sign_data(rsa_priv, h)
        encrypted_value = paillier_encrypt(paillier_pub, value)

        data_list.append({
            'hospital_id': i + 1,
            'data': value,
            'hash': h,
            'signature': sig.hex(),
            'encrypted': encrypted_value
        })
        print(f"Hospital {i+1} data summary:")
        print(json.dumps(data_list[-1], indent=4))
        print("-" * 50)

    print("\n--- Data sent to server ---\n")
    return data_list, rsa_pub, paillier_pub, paillier_priv

# ===============================
# --- SERVER SIDE ---
# ===============================

def verify_signature(public_key, data_hash, signature_hex):
    try:
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            data_hash.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"Signature verification passed for hash {data_hash[:10]}...\n")
        return True
    except Exception:
        print(f"Signature verification failed for hash {data_hash[:10]}...\n")
        return False

def server_verify_data(data_list, rsa_pub, paillier_pub, paillier_priv):
    hashes_seen = set()
    tampered = False

    for item in data_list:
        print(f"\n--- Verifying Hospital {item['hospital_id']} ---")
        recalculated_hash = sha256_hash(str(item['data']))

        if recalculated_hash != item['hash']:
            print(f"Tampering detected for Hospital {item['hospital_id']} (Hash mismatch)")
            tampered = True

        if recalculated_hash in hashes_seen:
            print(f"Duplicate hash found (Hospital {item['hospital_id']}) - Possible tampering!")
            tampered = True
        else:
            hashes_seen.add(recalculated_hash)

        if not verify_signature(rsa_pub, item['hash'], item['signature']):
            print(f"Invalid signature for Hospital {item['hospital_id']}")
            tampered = True

    if not tampered:
        print("All hashes and signatures verified successfully — No tampering detected.\n")

    # --- Homomorphic Addition Demonstration ---
    if len(data_list) >= 2:
        print("\n=== HOMOMORPHIC ADDITION DEMONSTRATION ===\n")
        c1, c2 = data_list[0]['encrypted'], data_list[1]['encrypted']
        print(f"Encrypted value 1 (Hospital 1): {c1}")
        print(f"Encrypted value 2 (Hospital 2): {c2}")

        sum_encrypted = paillier_add(paillier_pub, c1, c2)
        decrypted_sum = paillier_decrypt(paillier_priv, paillier_pub, sum_encrypted)

        print(f"Decrypted homomorphic sum: {decrypted_sum}")
        expected_sum = data_list[0]['data'] + data_list[1]['data']
        print(f"Expected sum: {data_list[0]['data']} + {data_list[1]['data']} = {expected_sum}\n")

# ===============================
# --- MAIN DRIVER ---
# ===============================

if __name__ == "__main__":
    data_list, rsa_pub, paillier_pub, paillier_priv = client_send_data()
    print("\n--- SERVER VERIFICATION ---\n")
    server_verify_data(data_list, rsa_pub, paillier_pub, paillier_priv)
