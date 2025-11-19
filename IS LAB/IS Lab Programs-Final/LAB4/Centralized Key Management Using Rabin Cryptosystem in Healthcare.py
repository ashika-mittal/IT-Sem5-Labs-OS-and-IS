

"""
rabin_kms.py

Rabin KMS:
- Generate Rabin keypairs (p,q primes where p%4==3 and q%4==3)
- Store public key (n) and encrypted private (p,q) in secure store (AES-encrypted file)
- Provide a Flask API to request keys / revoke / list
- Key renewal & auditing functions (callable)
- Simple Rabin encryption/decryption with 2-byte checksum to choose the correct root
"""

import os, json, time, logging
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
from base64 import b64encode, b64decode
from flask import Flask, request, jsonify

# -------- config & logging --------
STORE_FILE = "rabin_private_store.bin"
PUBSTORE_FILE = "rabin_public_store.json"
MASTER_PASSPHRASE = os.environ.get("RABIN_KMS_PASSPHRASE", "change_this_master_passphrase")
KEY_RENEWAL_SECONDS = 60*60*24*365  # 12 months ~ 365 days

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RabinKMS")

# ---------- AES helper to securely store private data (GCM mode) ----------
def derive_master_key(passphrase):
    # simple key derivation: SHA256 of passphrase (demo). Use PBKDF2 in prod.
    return sha256(passphrase.encode()).digest()

def aes_encrypt_bytes(key, plaintext):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return b64encode(iv + tag + ct).decode()

def aes_decrypt_bytes(key, b64data):
    raw = b64decode(b64data)
    iv = raw[:12]
    tag = raw[12:28]
    ct = raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

# ---------- Rabin cryptosystem helpers ----------
def generate_rabin_keypair(bits=1024):
    # p,q primes where p % 4 == 3 and q % 4 == 3
    while True:
        p = number.getPrime(bits//2)
        if p % 4 == 3:
            break
    while True:
        q = number.getPrime(bits//2)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return {'p': p, 'q': q, 'n': n, 'bits': bits}

def rabin_encrypt(n, message_bytes):
    # We embed a 2-byte checksum to later identify correct root.
    # message must be small enough: m < sqrt(n). We'll assume messages are short (e.g., symmetric key or small text).
    # For simplicity, prepend 2 bytes: checksum = SHA256(msg)[:2], then m = checksum||msg
    chk = sha256(message_bytes).digest()[:2]
    m = chk + message_bytes
    m_int = int.from_bytes(m, 'big')
    if m_int >= n:
        raise ValueError("Message too long for given modulus. Use hybrid encryption (encrypt symmetric key).")
    c = pow(m_int, 2, n)
    return c

def _sqrt_mod_p(a, p):
    # p % 4 == 3, sqrt = a^{(p+1)/4} mod p
    return pow(a, (p+1)//4, p)

def rabin_decrypt(p, q, c):
    n = p * q
    # compute square roots modulo p and q
    mp = _sqrt_mod_p(c % p, p)
    mq = _sqrt_mod_p(c % q, q)
    # combine with CRT -> four candidates
    # using extended euclid to compute coefficients
    def egcd(a,b):
        if b==0: return (a,1,0)
        g,x1,y1 = egcd(b,a%b)
        return (g, y1, x1 - (a//b)*y1)
    g, yp, yq = egcd(p,q)
    if g != 1:
        raise Exception("p and q not coprime")
    # roots:
    r1 = (yp*p*mq + yq*q*mp) % n
    r2 = n - r1
    r3 = (yp*p*mq - yq*q*mp) % n
    r4 = n - r3
    candidates = [r1, r2, r3, r4]
    # convert to bytes and check checksum matches
    for r in candidates:
        m_bytes = r.to_bytes((r.bit_length()+7)//8, 'big')
        if len(m_bytes) < 3:
            continue
        chk = sha256(m_bytes[2:]).digest()[:2]
        if m_bytes[:2] == chk:
            return m_bytes[2:]
    raise Exception("Failed to disambiguate root - message not found among candidates")

# ---------- Key Store management ----------
class RabinKMS:
    def __init__(self, master_passphrase=MASTER_PASSPHRASE):
        self.master_key = derive_master_key(master_passphrase)
        # load public store (cleartext) and private store (encrypted)
        if os.path.exists(PUBSTORE_FILE):
            with open(PUBSTORE_FILE,'r') as f:
                self.pubstore = json.load(f)
        else:
            self.pubstore = {}  # name -> {n, bits, created_at, revoked}
        if os.path.exists(STORE_FILE):
            with open(STORE_FILE,'r') as f:
                enc_blob = f.read()
                raw = aes_decrypt_bytes(self.master_key, enc_blob)
                self.privstore = json.loads(raw.decode())
        else:
            self.privstore = {}  # name -> {p,q,created_at,expires_at}
        logger.info("RabinKMS initialized")

    def generate_keys_for_entity(self, name, bits=1024):
        if name in self.pubstore and not self.pubstore[name].get('revoked', False):
            raise Exception("Entity already has active key")
        obj = generate_rabin_keypair(bits)
        p,q,n = obj['p'], obj['q'], obj['n']
        now = int(time.time())
        # store public
        self.pubstore[name] = {'n': str(n), 'bits': bits, 'created_at': now, 'revoked': False}
        # store private encrypted in privstore
        self.privstore[name] = {'p': str(p), 'q': str(q), 'created_at': now, 'expires_at': now + KEY_RENEWAL_SECONDS}
        self._persist()
        logger.info(f"Generated keys for {name}")
        return {'name': name, 'n': str(n), 'bits': bits}

    def get_public(self, name):
        if name not in self.pubstore:
            raise Exception("Unknown entity")
        if self.pubstore[name].get('revoked', False):
            raise Exception("Entity revoked")
        return {'name': name, 'n': self.pubstore[name]['n'], 'bits': self.pubstore[name]['bits']}

    def revoke(self, name):
        if name in self.pubstore:
            self.pubstore[name]['revoked'] = True
        if name in self.privstore:
            self.privstore[name]['revoked'] = True
        self._persist()
        logger.info(f"Revoked {name}")

    def get_private_decrypted(self, name):
        # Returns integers p,q for server-side operations (should be restricted)
        if name not in self.privstore:
            raise Exception("No private info")
        if self.pubstore.get(name,{}).get('revoked', False):
            raise Exception("Revoked")
        p = int(self.privstore[name]['p'])
        q = int(self.privstore[name]['q'])
        return p,q

    def renew_keys(self, name, bits=1024):
        # revoke old and generate new
        self.revoke(name)
        return self.generate_keys_for_entity(name, bits=bits)

    def auto_renew_all(self):
        now = int(time.time())
        rotated = []
        for name, rec in list(self.privstore.items()):
            if rec.get('expires_at', 0) <= now:
                self.renew_keys(name, bits=self.pubstore[name]['bits'])
                rotated.append(name)
        if rotated:
            logger.info("Auto renewed keys for: " + ", ".join(rotated))
        return rotated

    def _persist(self):
        # write public store plain
        with open(PUBSTORE_FILE,'w') as f:
            json.dump(self.pubstore, f, indent=2)
        # write private store encrypted
        raw = json.dumps(self.privstore).encode()
        enc = aes_encrypt_bytes(self.master_key, raw)
        with open(STORE_FILE,'w') as f:
            f.write(enc)

# ---------- Minimal Flask API ----------
app = Flask(__name__)
kms = RabinKMS()

@app.route('/generate', methods=['POST'])
def api_generate():
    data = request.json or {}
    name = data.get('name')
    bits = int(data.get('bits', 1024))
    if not name:
        return jsonify({'error':'name required'}), 400
    try:
        obj = kms.generate_keys_for_entity(name, bits=bits)
        return jsonify({'status':'ok','public':obj})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/get_public/<name>', methods=['GET'])
def api_get_public(name):
    try:
        pub = kms.get_public(name)
        return jsonify({'status':'ok','public':pub})
    except Exception as e:
        return jsonify({'error':str(e)}), 404

@app.route('/revoke', methods=['POST'])
def api_revoke():
    data = request.json or {}
    name = data.get('name')
    if not name:
        return jsonify({'error':'name required'}), 400
    kms.revoke(name)
    return jsonify({'status':'ok'})

@app.route('/list', methods=['GET'])
def api_list():
    return jsonify({'pubstore': kms.pubstore})

# helper endpoints for encrypt/decrypt small messages (demo only)
@app.route('/encrypt', methods=['POST'])
def api_encrypt():
    data = request.json or {}
    name = data.get('name')
    message = data.get('message')
    if not name or not message:
        return jsonify({'error':'name and message required'}), 400
    pub = kms.get_public(name)
    n = int(pub['n'])
    c = rabin_encrypt(n, message.encode())
    return jsonify({'ciphertext': str(c)})

@app.route('/decrypt', methods=['POST'])
def api_decrypt():
    data = request.json or {}
    name = data.get('name')
    ciphertext = data.get('ciphertext')
    if not name or not ciphertext:
        return jsonify({'error':'name and ciphertext required'}), 400
    p,q = kms.get_private_decrypted(name)
    c = int(ciphertext)
    try:
        m = rabin_decrypt(p,q,c)
        return jsonify({'message': m.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == "__main__":
    # Demo run: create two hospitals and show generation + encryption/decryption
    print("Starting Rabin KMS demo (not launching Flask).")
    # demo generation:
    kms.generate_keys_for_entity("HospitalA", bits=1024)
    kms.generate_keys_for_entity("ClinicB", bits=1024)
    pub = kms.get_public("HospitalA")
    print("HospitalA public n (len bits):", len(str(pub['n'])))
    # demonstrate encrypt/decrypt short message (demo)
    msg = b"patient-42"
    n = int(pub['n'])
    c = rabin_encrypt(n, msg)
    print("ciphertext int size:", c.bit_length())
    p,q = kms.get_private_decrypted("HospitalA")
    m = rabin_decrypt(p,q,c)
    print("Recovered message:", m)
    # To run API server: run `python rabin_kms.py` and then use Flask endpoints
    # app.run(port=5000, debug=True)


# import random, time

# # --- Rabin Key Generation ---
# def rabin_keygen(bits=512):
#     def prime4(): 
#         while True:
#             p=random.getrandbits(bits)
#             if p%4==3 and all(p%d for d in range(3,int(p**0.5),2)): return p
#     p,q=prime4(),prime4()
#     n=p*q
#     return (n,),(p,q)

# # --- Key Manager ---
# class RabinKeyManager:
#     def __init__(self): self.db={}; self.logs=[]
#     def gen(self,hosp): 
#         pub,priv=rabin_keygen(); self.db[hosp]=(pub,priv)
#         self.logs.append((time.time(),f"Generated {hosp}"))
#     def get(self,hosp): return self.db[hosp][0]
#     def revoke(self,hosp): self.db.pop(hosp,None); self.logs.append((time.time(),f"Revoked {hosp}"))
#     def renew(self,hosp): self.gen(hosp); self.logs.append((time.time(),f"Renewed {hosp}"))

# # --- Usage ---
# km=RabinKeyManager()
# km.gen("Hospital_A"); km.gen("Clinic_B")
# print("Hospital_A public key:",km.get("Hospital_A"))
# km.renew("Clinic_B"); km.revoke("Hospital_A")
# print("Logs:",km.logs)

