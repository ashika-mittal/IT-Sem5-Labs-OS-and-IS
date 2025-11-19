#!/usr/bin/env python3
"""
Client:
 - Connects to server, receives server public key
 - Generates RSA keypair
 - Encrypts user message using columnar transposition cipher
 - Encrypts that key using server's RSA public key (OAEP)
 - Signs ciphertext using client's RSA private key
 - Sends payload to server, then closes connection cleanly
"""

import socket, json, base64, random, string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# ----------------------------------------------------------
# Columnar Transposition Cipher (Keyed)
# ----------------------------------------------------------
def sanitize(s):
    return "".join(ch for ch in s.upper() if ch.isalpha())

def columnar_encrypt(plain, key):
    s = sanitize(plain)
    ncol = len(key)
    rows = (len(s) + ncol - 1) // ncol
    matrix = [['X'] * ncol for _ in range(rows)]
    it = iter(s)
    for r in range(rows):
        for c in range(ncol):
            try:
                matrix[r][c] = next(it)
            except StopIteration:
                break
    order = sorted([(ch, i) for i, ch in enumerate(key)])
    cipher = ""
    for _, col in order:
        for r in range(rows):
            cipher += matrix[r][col]
    return cipher

# ----------------------------------------------------------
# RSA Helper Functions
# ----------------------------------------------------------
def gen_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def rsa_encrypt_oaep(pubkey_pem, plaintext_str):
    pub = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(pub)
    return base64.b64encode(cipher.encrypt(plaintext_str.encode('utf-8'))).decode('utf-8')

def sign_message(privkey, message_bytes):
    h = SHA256.new(message_bytes)
    sig = pkcs1_15.new(privkey).sign(h)
    return base64.b64encode(sig).decode('utf-8')

# ----------------------------------------------------------
# Client Logic
# ----------------------------------------------------------
def run_client(server_host='127.0.0.1', server_port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"<<END_PUBKEY>>" in data:
                break

        parts = data.split(b"<<END_PUBKEY>>")
        server_pub_pem = parts[0].decode('utf-8').strip()
        print("✅ Received server public key")

        client_priv, client_pub = gen_rsa_keypair()
        client_pub_pem = client_pub.export_key().decode('utf-8')

        message = input("\n✉️  Enter plaintext message to send: ").strip()
        if not message:
            print("❌ No message entered.")
            return

        col_key = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))
        print("Using columnar key:", col_key)

        ciphertext = columnar_encrypt(message, col_key)
        orig_len = len(sanitize(message))

        print("\n--- SENT DATA ---")
        print("Ciphertext:", ciphertext)
        enc_key_b64 = rsa_encrypt_oaep(server_pub_pem, col_key)
        print("Encrypted key (base64):", enc_key_b64[:60] + "...")
        signature_b64 = sign_message(client_priv, ciphertext.encode('utf-8'))
        print("Signature (base64):", signature_b64[:60] + "...")

        payload = {
            'client_pubkey': client_pub_pem,
            'enc_key': enc_key_b64,
            'ciphertext': ciphertext,
            'signature': signature_b64,
            'orig_len': orig_len
        }

        payload_bytes = json.dumps(payload).encode('utf-8')
        s.sendall(payload_bytes)
        print(f"📤 Sent {len(payload_bytes)} bytes to server.")
        s.shutdown(socket.SHUT_WR)
        print("\n✅ Message sent successfully to server.")


if __name__ == '__main__':
    run_client()
