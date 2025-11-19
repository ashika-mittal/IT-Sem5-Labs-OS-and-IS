import socket
import pickle
import hashlib
from Crypto.Util.number import getPrime, inverse
from random import randint

# ------------------ ElGamal Verification ------------------
def generate_elgamal_keys():
    p = getPrime(256)
    g = randint(2, p - 1)
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def verify_elgamal_signature(p, g, y, msg_hash, r, s):
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, msg_hash, p)
    return v1 == v2

# ------------------ Paillier (Homomorphic Addition) ------------------
def generate_paillier_keys(bits=256):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    g = n + 1
    lam = (p - 1) * (q - 1)
    mu = inverse(lam, n)
    return (n, g), (lam, mu, n)

def decrypt_paillier(c, priv):
    lam, mu, n = priv
    x = pow(c, lam, n * n)
    l = (x - 1) // n
    return (l * mu) % n

# ------------------ Tampering Detection Function ------------------
def detect_tampering(hashes):
    seen = set()
    for h in hashes:
        if h in seen:
            return "⚠️ Data Tampered (Duplicate hash found)"
        seen.add(h)
    return "✅ Data Safe (All hashes unique)"

# ------------------ SERVER START ------------------
def run_server():
    host = 'localhost'
    port = 65432

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("🏥 MedCare Server running on port", port)

    # Generate Paillier keys for secure aggregation
    pub_paillier, priv_paillier = generate_paillier_keys()
    n, g = pub_paillier

    all_hashes = []
    combined_encrypted_sum = 1

    num_clients = int(input("Enter number of hospitals to receive data from: "))

    for i in range(num_clients):
        print(f"\n💡 Waiting for Hospital-{i+1} connection...")
        conn, addr = server_socket.accept()
        print(f"✅ Connected with {addr}")

        data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet

        if not data:
            print("❌ No data received from client.")
            continue

        try:
            received = pickle.loads(data)
            enc_value = received["enc_value"]
            msg_hash = received["hash"]
            r, s = received["signature"]
            elgamal_pub = received["elgamal_pub"]

            p, g, y = elgamal_pub
            hash_int = int(msg_hash, 16) % p

            # Verify ElGamal signature
            if verify_elgamal_signature(p, g, y, hash_int, r, s):
                print(f"✅ Hospital-{i+1} signature verified.")
            else:
                print(f"❌ Hospital-{i+1} signature invalid!")

            # Collect hashes for tampering detection
            all_hashes.append(msg_hash)

            # Homomorphic addition (Paillier): multiply ciphertexts mod n^2
            combined_encrypted_sum = (combined_encrypted_sum * enc_value) % (n * n)

        except Exception as e:
            print(f"❌ Error processing Hospital-{i+1}: {e}")
            continue

        conn.close()

    # ------------------ Post-Processing ------------------
    print("\n🔍 Running integrity and aggregation checks...")

    # Check for duplicate hashes (tampering)
    integrity_status = detect_tampering(all_hashes)
    print("[Integrity Check]:", integrity_status)

    # Decrypt homomorphic addition result
    decrypted_sum = decrypt_paillier(combined_encrypted_sum, priv_paillier)
    print("🧮 Secure aggregated sum of all hospital data:", decrypted_sum)

    print("\n✅ Server processing complete.")

if __name__ == "__main__":
    run_server()
