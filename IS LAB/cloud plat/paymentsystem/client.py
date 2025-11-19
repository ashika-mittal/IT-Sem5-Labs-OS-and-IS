# client.py
# Client:
# - Connect to server; receive Paillier pub + RSA pub (same socket).
# - Prepare ≥2 sellers with ≥2 transactions each.
# - Paillier-encrypt each amount with server's pub.
# - Send encrypted transactions over SAME socket.
# - Receive summary JSON; verify SHA-256 and RSA; print full rubric output.
# - Ultra-verbose logging so you never see "blank".

import socket, json, hashlib, random, sys
from math import gcd

HOST, PORT = "127.0.0.1", 60606

def log(*a): print("[client]", *a, flush=True)

# -------- Paillier encryption --------
def paillier_encrypt(pub, m):
    n, g = pub["n"], pub["g"]
    nsq = n * n
    r = random.randrange(1, n)
    while gcd(r, n) != 1:
        r = random.randrange(1, n)
    return int((pow(g, m, nsq) * pow(r, n, nsq)) % nsq)

# -------- RSA verify --------
def rsa_verify_bytes(data: bytes, signature: int, pub):
    n, e = pub["n"], pub["e"]
    h = int.from_bytes(hashlib.sha256(data).digest(), "big") % n
    return pow(int(signature), int(e), int(n)) == h

def main():
    log(f"Connecting to {HOST}:{PORT} ...")
    with socket.socket() as s:
        s.settimeout(10.0)
        s.connect((HOST, PORT))
        log("Connected.")

        # Read key banner
        buf = b""
        while b"<<ENDKEYS>>" not in buf:
            chunk = s.recv(8192)
            if not chunk:
                raise RuntimeError("Server closed before sending keys")
            buf += chunk

        key_json, leftover = buf.split(b"<<ENDKEYS>>", 1)
        keys = json.loads(key_json.decode())
        pai_pub = keys["paillier_pub"]
        rsa_pub = keys["rsa_pub"]
        log("Received keys. Paillier n bits:", pai_pub["n"].bit_length())

        # Sellers and amounts (edit freely)
        sellers_plain = [
            {"name": "Alice_Store", "amounts": [120, 250, 90]},
            {"name": "Bob_Shop",    "amounts": [75, 300, 60, 40]},
        ]
        log("Prepared plain sellers data.")

        # Encrypt amounts with Paillier
        sellers_enc = []
        for srec in sellers_plain:
            enc_list = [paillier_encrypt(pai_pub, amt) for amt in srec["amounts"]]
            sellers_enc.append({"name": srec["name"], "enc_amounts": enc_list})
        log("Encrypted all amounts with Paillier.")

        # Send request on SAME socket
        req = {"sellers": sellers_enc}
        req_bytes = json.dumps(req).encode()
        s.sendall(req_bytes)
        log("Sent request bytes:", len(req_bytes))

        # Read response (may already have some bytes in 'leftover')
        data = leftover
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            data += chunk
    log("Received response bytes:", len(data))
    if not data.strip():
        log("❌ Empty response from server. Check server logs.")
        sys.exit(1)

    # Parse response
    try:
        resp = json.loads(data.decode())
    except Exception as e:
        log("JSON decode error on response:", e)
        log("Raw response head:", data[:120])
        sys.exit(1)

    if not resp.get("ok"):
        log("Server error:", resp)
        sys.exit(1)

    # Verify summary
    summary_text = resp["summary_text"].encode()
    sha_server  = resp["sha256"]
    sig         = int(resp["signature"])

    sha_client = hashlib.sha256(summary_text).hexdigest()
    hash_ok = (sha_client == sha_server)
    sig_ok  = rsa_verify_bytes(summary_text, sig, rsa_pub)

    # Print rubric-required summary
    print("\n=== Transaction Summary (from Gateway) ===")
    for sec in resp["sections"]:
        print(f"Seller Name: {sec['seller']}")
        print(f"  Individual Transaction Amounts (Plain): {sec['plain']}")
        print(f"  Encrypted Transaction Amounts        : {sec['encrypted']}")
        print(f"  Decrypted Transaction Amounts        : {sec['dec_each']}")
        print(f"  Total Encrypted Transaction Amount   : {sec['enc_total']}")
        print(f"  Total Decrypted Transaction Amount   : {sec['dec_total']}\n")

    print("--- Summary Text ---")
    print(resp["summary_text"])
    print("--------------------")
    print("SHA-256(summary):", sha_server)
    print("Digital Signature Status: Signed by Payment Gateway (RSA)")
    print("Signature Verification Result:", "✅ Valid" if sig_ok else "❌ Invalid")
    print("Hash Recomputed Match:", "✅ Yes" if hash_ok else "❌ No")

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        log("FATAL:", ex)
        sys.exit(1)