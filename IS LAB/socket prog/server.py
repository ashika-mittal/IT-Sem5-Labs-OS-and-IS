#!/usr/bin/env python3
import socket, json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# -------------------- Columnar Transposition --------------------
def sanitize(s):
    return "".join(ch for ch in s.upper() if ch.isalpha())

def columnar_decrypt(cipher, key, orig_len):
    cipher = "".join(ch for ch in cipher if ch.isalpha())
    ncol = len(key)
    rows = (len(cipher) + ncol - 1) // ncol
    order = sorted([(ch, i) for i, ch in enumerate(key)])
    total_cells = rows * ncol
    cipher = cipher.ljust(total_cells, 'X')
    cols = [''] * ncol
    idx = 0
    for _, col_idx in order:
        cols[col_idx] = cipher[idx: idx + rows]
        idx += rows
    plaintext_chars = []
    for r in range(rows):
        for c in range(ncol):
            plaintext_chars.append(cols[c][r])
    plaintext = ''.join(plaintext_chars)[:orig_len]
    return plaintext

# -------------------- RSA Helpers --------------------
def gen_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def rsa_decrypt_oaep(privkey, ciphertext_b64):
    ct = base64.b64decode(ciphertext_b64)
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ct).decode('utf-8')

def verify_signature(pubkey_pem, message_bytes, signature_b64):
    pub = RSA.import_key(pubkey_pem)
    h = SHA256.new(message_bytes)
    sig = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(pub).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False

# -------------------- SERVER --------------------
def run_server(host='0.0.0.0', port=65432):
    print("🔐 Generating server RSA keypair (2048 bits)...")
    server_priv, server_pub = gen_rsa_keypair()
    server_pub_pem = server_pub.export_key().decode('utf-8')
    print("✅ Server ready. Listening on port", port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print(f"\n💡 Connected by {addr}")
            # send server public key
            conn.sendall(server_pub_pem.encode('utf-8') + b"<<END_PUBKEY>>")

            # ----------- FIXED RECEIVE LOOP -----------
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            # ------------------------------------------

            if not data:
                print("❌ No data received from client.")
                return

            print("\n📦 Raw data received (truncated):")
            print(data.decode('utf-8')[:200], "...\n")

            try:
                payload = json.loads(data.decode('utf-8'))
            except Exception as e:
                print("❌ Failed to parse JSON:", e)
                return

            client_pub_pem = payload['client_pubkey']
            enc_key_b64 = payload['enc_key']
            ciphertext = payload['ciphertext'].strip()
            signature_b64 = payload['signature']
            orig_len = int(payload['orig_len'])

            print("--- RECEIVED DATA ---")
            print("Ciphertext:", ciphertext)
            print("Encrypted key (base64):", enc_key_b64[:60] + "...")
            print("Signature (base64):", signature_b64[:60] + "...")

            try:
                col_key = rsa_decrypt_oaep(server_priv, enc_key_b64)
            except Exception as e:
                print("❌ Failed to decrypt column key:", e)
                conn.sendall(b"ERR: key decryption failed")
                return

            print("\nRecovered columnar key:", col_key)

            ok = verify_signature(client_pub_pem, ciphertext.encode('utf-8'), signature_b64)
            if not ok:
                print("❌ Signature verification FAILED!")
                conn.sendall(b"ERR: signature invalid")
                return
            else:
                print("✅ Signature verified successfully")

            plaintext = columnar_decrypt(ciphertext, col_key, orig_len)
            print("\n--- DECRYPTION RESULT ---")
            print("Plaintext:", plaintext)
            print("\n✅ Communication complete")

            conn.sendall(b"OK: message received and verified")

if __name__ == '__main__':
    run_server()
