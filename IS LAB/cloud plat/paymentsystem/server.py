# server.py
# Payment Gateway:
# - Generates Paillier (additive HE) + RSA (signing) keys.
# - Sends Paillier pub + RSA pub as a JSON banner ending with <<ENDKEYS>>.
# - Receives sellers' encrypted transactions on the SAME connection.
# - Homomorphically totals, decrypts each amount & total.
# - Builds deterministic summary text, SHA-256, RSA signs, returns JSON.
# - Ultra-verbose logging to prevent "blank" confusion.

import socket, json, hashlib, sys
from Crypto.Util.number import getPrime, inverse
from math import gcd
from typing import List, Dict, Any

HOST, PORT = "127.0.0.1", 60606

def log(*a): print("[server]", *a, flush=True)

# -------- Paillier (additive HE) --------
def paillier_keygen(bits=512):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    while p == q:
        q = getPrime(bits//2)
    n = p * q
    n2 = n * n
    g = n + 1
    lam = ((p-1)*(q-1)) // gcd(p-1, q-1)  # lcm via product/gcd
    def L(u): return (u - 1) // n
    mu = inverse(L(pow(g, lam, n2)), n)
    pub  = {"n": int(n), "g": int(g)}
    priv = {"n": int(n), "n2": int(n2), "lam": int(lam), "mu": int(mu)}
    return pub, priv

def paillier_decrypt(c, priv):
    n, n2, lam, mu = priv["n"], priv["n2"], priv["lam"], priv["mu"]
    def L(u): return (u - 1) // n
    x = pow(int(c), lam, n2)
    return int((L(x) * mu) % n)

def paillier_add_enc(c_acc, c_new, n2):
    return (int(c_acc) * int(c_new)) % n2

# -------- RSA (signature) --------
def rsa_keygen(bits=1024):
    p, q = getPrime(bits//2), getPrime(bits//2)
    while p == q:
        q = getPrime(bits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = inverse(e, phi)
    return {"n": int(n), "e": int(e)}, {"n": int(n), "d": int(d)}

def rsa_sign_bytes(data: bytes, priv):
    n, d = priv["n"], priv["d"]
    h = int.from_bytes(hashlib.sha256(data).digest(), "big")
    return int(pow(h, d, n))

# -------- Summary text (deterministic) --------
def build_summary_text(sections: List[Dict[str, Any]]) -> bytes:
    lines = []
    for sec in sections:
        lines.append(f"Seller: {sec['seller']}")
        lines.append(f"  Plain: {sec['plain']}")
        lines.append(f"  Encrypted: {sec['encrypted']}")
        lines.append(f"  DecEach: {sec['dec_each']}")
        lines.append(f"  EncTotal: {sec['enc_total']}")
        lines.append(f"  DecTotal: {sec['dec_total']}")
    return ("\n".join(lines)).encode()

def serve_once(conn: socket.socket):
    # 1) Keys
    pai_pub, pai_priv = paillier_keygen(bits=512)
    rsa_pub, rsa_priv = rsa_keygen(bits=1024)
    n2 = pai_pub["n"] * pai_pub["n"]
    log("Paillier n bits:", pai_pub["n"].bit_length())

    # 2) Send key banner
    banner = json.dumps({"paillier_pub": pai_pub, "rsa_pub": rsa_pub}).encode() + b"<<ENDKEYS>>"
    conn.sendall(banner)
    log("Sent key banner to client.")

    # 3) Receive full request on SAME socket
    data = b""
    while True:
        chunk = conn.recv(65535)
        if not chunk:
            break
        data += chunk

    if not data.strip():
        log("Empty request body from client; sending error JSON.")
        conn.sendall(json.dumps({"ok": False, "error": "empty request"}).encode())
        return

    log("Received request bytes:", len(data))
    try:
        req = json.loads(data.decode())
    except Exception as e:
        log("JSON decode error:", e)
        conn.sendall(json.dumps({"ok": False, "error": f"bad json: {e}"}).encode())
        return

    sellers = req.get("sellers", [])
    if not sellers:
        log("No 'sellers' provided.")
        conn.sendall(json.dumps({"ok": False, "error": "no sellers"}).encode())
        return
    log("Sellers received:", [s['name'] for s in sellers])

    # 4) Decrypt each amount; homomorphic totals
    sections = []
    for srec in sellers:
        name = srec["name"]
        enc_list = [int(x) for x in srec["enc_amounts"]]
        dec_each = [paillier_decrypt(c, pai_priv) for c in enc_list]
        enc_total = 1
        for c in enc_list:
            enc_total = paillier_add_enc(enc_total, c, n2)
        dec_total = paillier_decrypt(enc_total, pai_priv)
        sections.append({
            "seller": name,
            "plain": dec_each,           # decrypted individual
            "encrypted": enc_list,       # ciphertexts
            "dec_each": dec_each,        # explicit per rubric
            "enc_total": int(enc_total),
            "dec_total": int(dec_total),
        })
    log("Built sections for summary.")

    # 5) Summary + sign
    summary_bytes = build_summary_text(sections)
    sig = rsa_sign_bytes(summary_bytes, rsa_priv)
    sha256_hex = hashlib.sha256(summary_bytes).hexdigest()
    log("Summary SHA-256:", sha256_hex[:16], "...")

    # 6) Respond
    resp = {
        "ok": True,
        "sections": sections,
        "summary_text": summary_bytes.decode(),
        "sha256": sha256_hex,
        "signature": sig,
        "digital_signature_status": "Signed by Payment Gateway (RSA)",
    }
    payload = json.dumps(resp).encode()
    conn.sendall(payload)
    log("Response bytes sent:", len(payload))

def main():
    log(f"Starting gateway on {HOST}:{PORT}")
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT)); s.listen(5)
        while True:
            conn, addr = s.accept()
            with conn:
                log("Client connected:", addr)
                serve_once(conn)
                log("Session complete.\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Shutting down.")
        sys.exit(0)