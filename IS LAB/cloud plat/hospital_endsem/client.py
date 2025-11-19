# hospital_client.py
# Hospital client: input integer -> SHA-256 hash -> ElGamal sign (on hash)
# -> Paillier encrypt (value) -> send JSON to server.

import socket, json, hashlib, random
from math import gcd
from Crypto.Util.number import getPrime, inverse

HOST, PORT = "127.0.0.1", 65432

# --------- ElGamal (signature) ---------
def elgamal_keygen(bits=256):
    p = getPrime(bits)
    g = random.randrange(2, p - 1)           # simple generator candidate
    x = random.randrange(2, p - 2)           # private
    y = pow(g, x, p)                         # public component
    return (p, g, y), (p, g, x)

def elgamal_sign(hash_hex, priv):
    p, g, x = priv
    H = int(hash_hex, 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = (pow(k, -1, p - 1) * (H - x * r)) % (p - 1)
    return {"r": int(r), "s": int(s)}

# --------- Paillier encrypt ---------
def paillier_encrypt(pub, m):
    n, g = pub["n"], pub["g"]; n2 = n*n
    r = random.randrange(1, n)
    while gcd(r, n) != 1:
        r = random.randrange(1, n)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def main():
    # connect and receive Paillier pub
    with socket.socket() as s:
        s.connect((HOST, PORT))
        # read until marker
        buf = b""
        while b"<<ENDKEYS>>" not in buf:
            buf += s.recv(8192)
        keys_json, _ = buf.split(b"<<ENDKEYS>>", 1)
        srv = json.loads(keys_json.decode())
        pai_pub = srv["paillier_pub"]

    # Hospital input & keys
    hospital_id = input("Hospital ID (e.g., Hospital-A): ").strip()
    value = int(input("Enter confidential integer value: ").strip())

    elg_pub, elg_priv = elgamal_keygen(bits=256)

    # Hash of the value (integrity)
    hhex = hashlib.sha256(str(value).encode()).hexdigest()

    # ElGamal signature on hash
    sig = elgamal_sign(hhex, elg_priv)

    # Paillier encrypt the integer
    ct = paillier_encrypt(pai_pub, value)

    # Prepare packet (include plaintext only for LAB hash recompute)
    packet = {
        "hospital_id": hospital_id,
        "paillier_cipher": int(ct),
        "hash_hex": hhex,
        "signature": sig,
        "elgamal_pub": {"p": int(elg_pub[0]), "g": int(elg_pub[1]), "y": int(elg_pub[2])},
        "plain_for_verification": int(value)   # lab-only, lets server recompute hash
    }

    # Reconnect, send packet
    with socket.socket() as s2:
        s2.connect((HOST, PORT))
        s2.sendall(json.dumps(packet).encode())

    print("\n[client] Sent successfully.")
    print("  ID      :", hospital_id)
    print("  value   :", value)
    print("  hash    :", hhex)
    print("  sig (r,s):", (sig['r'], sig['s']))
    print("  cipher  :", ct)

if __name__ == "__main__":
    main()