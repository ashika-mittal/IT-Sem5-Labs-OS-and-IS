# server_hybrid.py
# Secure multi-hospital aggregation: verifies ElGamal signatures on SHA-256 hashes,
# checks duplicate hashes (tampering alert), homomorphically sums Paillier ciphertexts,
# and (optionally) decrypts the final sum.

import socket, json
from Crypto.Util.number import getPrime, inverse
from math import gcd

HOST, PORT = "127.0.0.1", 65432

# ---------------- Paillier ----------------
def paillier_keygen(bits=512):
    p, q = getPrime(bits//2), getPrime(bits//2)
    while q == p:
        q = getPrime(bits//2)
    n = p*q
    n2 = n*n
    g = n + 1
    # λ = lcm(p-1, q-1)
    lam = ((p-1)*(q-1)) // gcd(p-1, q-1)
    # μ = (L(g^λ mod n^2))^{-1} mod n
    def L(u): return (u - 1) // n
    mu = inverse(L(pow(g, lam, n2)), n)
    return {"n": n, "g": g}, {"lam": lam, "mu": mu, "n": n, "n2": n2, "g": g}

def paillier_decrypt(c, priv):
    n, n2, lam, mu = priv["n"], priv["n2"], priv["lam"], priv["mu"]
    def L(u): return (u - 1) // n
    x = pow(c, lam, n2)
    return (L(x) * mu) % n

# ---------------- ElGamal verify ----------------
def elgamal_verify(hash_hex, sig, pub):
    p, g, y = pub["p"], pub["g"], pub["y"]
    r, s = sig["r"], sig["s"]
    if not (1 < r < p): return False
    H = int(hash_hex, 16) % (p - 1)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, H, p)
    return v1 == v2

def main():
    # Key setup
    pai_pub, pai_priv = paillier_keygen(bits=512)
    n, g = pai_pub["n"], pai_pub["g"]; n2 = n*n

    print(f"[server] Paillier n bits: {n.bit_length()}")
    print(f"[server] listening on {HOST}:{PORT}")

    # We’ll accept exactly two hospitals (A & B) for this demo
    received_packets = []
    all_hashes = {}
    tamper_alerts = []

    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(5)
        while len(received_packets) < 2:
            conn, addr = s.accept()
            with conn:
                # send Paillier public key first
                conn.sendall(json.dumps({"paillier_pub": pai_pub}).encode() + b"<<ENDKEYS>>")

                data = b""
                while True:
                    chunk = conn.recv(65535)
                    if not chunk: break
                    data += chunk

            try:
                pkt = json.loads(data.decode())
            except Exception as e:
                print("[-] bad JSON from client:", e)
                continue

            # expected fields:
            # {hospital_id, paillier_cipher, hash_hex, signature:{r,s}, elgamal_pub:{p,g,y},
            #  plain_for_verification (int)  <-- for lab integrity recompute only
            hid = pkt["hospital_id"]
            c   = int(pkt["paillier_cipher"])
            hhex = pkt["hash_hex"]
            sig = {"r": int(pkt["signature"]["r"]), "s": int(pkt["signature"]["s"])}
            ep  = {"p": int(pkt["elgamal_pub"]["p"]), "g": int(pkt["elgamal_pub"]["g"]), "y": int(pkt["elgamal_pub"]["y"])}

            # 1) Verify ElGamal signature over the hash
            sig_ok = elgamal_verify(hhex, sig, ep)
            print(f"[server] {hid} signature:", "OK" if sig_ok else "FAIL")

            # 2) Recompute hash from provided plaintext (lab-only check)
            plain = pkt.get("plain_for_verification")
            if plain is not None:
                recomputed = __import__("hashlib").sha256(str(int(plain)).encode()).hexdigest()
                print(f"[server] {hid} hash matches plaintext?",
                      "YES" if recomputed == hhex else "NO")
                if recomputed != hhex:
                    print(f"[server] WARNING: hash mismatch for {hid} (tamper on wire?)")

            # duplicate-hash alert across different hospitals
            if hhex in all_hashes and all_hashes[hhex] != hid:
                tamper_alerts.append((all_hashes[hhex], hid, hhex))
            else:
                all_hashes[hhex] = hid

            received_packets.append({"hid": hid, "cipher": c})

        # 3) Homomorphic addition (multiply ciphertexts mod n^2)
        enc_sum = 1
        for rec in received_packets:
            enc_sum = (enc_sum * rec["cipher"]) % (n2)

        # 4) Optional decryption of total
        dec_sum = paillier_decrypt(enc_sum, pai_priv)

        print("\n=== Aggregation Result ===")
        print("Tampering alerts:", tamper_alerts if tamper_alerts else "None")
        print("Encrypted sum   :", enc_sum)
        print("Decrypted total :", dec_sum)

if __name__ == "__main__":
    main()