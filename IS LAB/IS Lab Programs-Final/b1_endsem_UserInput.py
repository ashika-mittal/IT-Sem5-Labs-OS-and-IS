import socket
import threading
import time
import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import json

# ----------------------- Helper Functions -----------------------

def hash_sha256(messages):
    combined = "\n".join(messages)
    hash_obj = hashlib.sha256(combined.encode())
    return hash_obj.digest()

def lcm(a, b):
    return a * b // math.gcd(a, b)

# ----------------------- RSA Key Generation -----------------------

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

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

# ----------------------- Paillier Encryption -----------------------

def generate_keypair(p, q):
    n = p * q
    n_sq = n * n
    lam = lcm(p - 1, q - 1)
    g = n + 1

    x = pow(g, lam, n_sq)
    L = (x - 1) // n
    mu = pow(L, -1, n)

    return (n, g), (lam, mu)

def encrypt(pub_key, m):
    n, g = pub_key
    n_sq = n * n
    while True:
        r = random.randint(1, n - 1)
        if math.gcd(r, n) == 1:
            break
    return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

def decrypt(priv_key, pub_key, c):
    lam, mu = priv_key
    n, g = pub_key
    n_sq = n * n
    x = pow(c, lam, n_sq)
    L = (x - 1) // n
    return (L * mu) % n

def homomorphic_add(c1, c2, pub_key):
    n, g = pub_key
    return (c1 * c2) % (n * n)

# ----------------------- SERVER -----------------------

server_pub_key, server_priv_key = generate_keypair(17, 19)

def run_server(num_clients):
    HOST, PORT = "127.0.0.1", 65432
    sellers_summary = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening for {num_clients} clients...\n")

        for i in range(num_clients):
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096).decode()
                packet = json.loads(data)

                summary = packet["summary"]
                enc_sum = int(packet["enc_sum"])
                signature = bytes.fromhex(packet["signature"])
                pub_key_bytes = bytes.fromhex(packet["pub_key"])

                pub_key = serialization.load_pem_public_key(pub_key_bytes)
                digest = hash_sha256([summary])
                status = verify_signature(pub_key, digest, signature)

                decrypted_value = decrypt(server_priv_key, server_pub_key, enc_sum)

                print(f"[SERVER] Client {i+1} Summary:\n{summary}")
                print(f"[SERVER] Signature Valid: {status}")
                print(f"[SERVER] Decrypted Total Sum: {decrypted_value}\n")

                lines = summary.splitlines()
                name = lines[0].split(":-")[1].strip()

                sellers_summary.append({
                    "Seller": name,
                    "Summary": summary,
                    "Decrypted Total": decrypted_value,
                    "Signature Valid": status
                })

        print("\n========= FINAL TRANSACTION SUMMARY =========")
        for s_data in sellers_summary:
            print(json.dumps(s_data, indent=4))
        print("[SERVER] All clients served, exiting.")


# ----------------------- CLIENT -----------------------

def client_task(name, amt1, amt2):
    HOST, PORT = "127.0.0.1", 65432
    time.sleep(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Encrypt transaction amounts
        e1 = encrypt(server_pub_key, amt1)
        e2 = encrypt(server_pub_key, amt2)
        encrypted_sum = homomorphic_add(e1, e2, server_pub_key)

        priv_rsa, pub_rsa = generate_rsa_keys()

        summary = (
            f"Name:- {name}\n"
            f"Transaction amounts:- {amt1}, {amt2}\n"
            f"Encrypted:- {e1}, {e2}\n"
            f"Encrypted Sum:- {encrypted_sum}"
        )

        digest = hash_sha256([summary])
        signature = sign_document(priv_rsa, digest)

        packet = {
            "summary": summary,
            "enc_sum": encrypted_sum,
            "signature": signature.hex(),
            "pub_key": pub_rsa.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        }

        s.sendall(json.dumps(packet).encode())
        print(f"[CLIENT] Sent data for {name}\n")


# ----------------------- MAIN -----------------------

if __name__ == "__main__":
    num_clients = int(input("Enter number of sellers: "))
    sellers = []

    for i in range(num_clients):
        print(f"\n--- Seller {i+1} Details ---")
        name = input("Enter seller name: ")
        amt1 = int(input("Enter first transaction amount: "))
        amt2 = int(input("Enter second transaction amount: "))
        sellers.append((name, amt1, amt2))

    # Start server thread
    server_thread = threading.Thread(target=run_server, args=(num_clients,))
    server_thread.start()

    # Launch clients
    client_threads = []
    for name, amt1, amt2 in sellers:
        t = threading.Thread(target=client_task, args=(name, amt1, amt2))
        t.start()
        client_threads.append(t)

    for t in client_threads:
        t.join()

    server_thread.join()
