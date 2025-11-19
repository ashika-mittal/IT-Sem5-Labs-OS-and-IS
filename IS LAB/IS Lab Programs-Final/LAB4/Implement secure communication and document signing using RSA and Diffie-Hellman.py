# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import random

# # --- RSA Key Management ---
# class KeyManager:
#     def __init__(self): self.keys={}
#     def gen_key(self, sys): 
#         k=RSA.generate(2048); self.keys[sys]=(k,k.publickey())
#     def get_pub(self,sys): return self.keys[sys][1]
#     def revoke(self,sys): self.keys.pop(sys,None)

# # --- Diffie-Hellman ---
# def dh_key(): p=23; g=5; a=random.randint(1,10); A=pow(g,a,p); return a,A,p,g
# def dh_shared(priv, B, p): return pow(B,priv,p)

# # --- Secure Communication ---
# km=KeyManager()
# for s in ["Finance","HR","SupplyChain"]: km.gen_key(s)

# msg=b"Confidential Report"
# pub=km.get_pub("Finance")
# cipher=PKCS1_OAEP.new(pub).encrypt(msg)
# plain=PKCS1_OAEP.new(km.keys["Finance"][0]).decrypt(cipher)

# # --- DH Example (Finance ↔ HR) ---
# a,A,p,g=dh_key(); b,B,_,_=dh_key()
# shared1=dh_shared(a,B,p); shared2=dh_shared(b,A,p)

# print("Encrypted:",cipher[:20],"...")
# print("Decrypted:",plain)
# print("Shared Key Match:",shared1==shared2)



"""
securecorp_demo.py

Demo of a SecureCorp key-management + secure communication system:
- RSA keypairs for subsystems (register with KMS)
- Ephemeral Diffie-Hellman per-session to derive symmetric keys
- RSA used to encrypt ephemeral DH public values and for signatures
- KMS supports register, get_public, revoke
- Scalable: add new subsystems easily

NOT FOR PRODUCTION: This is an educational/demo implementation.
Use real crypto libraries (cryptography / PyCryptodome) and secure protocols (TLS, AES-GCM) in production.
"""

import secrets, hashlib, math, json, time
from dataclasses import dataclass

# ---------------- utilities: fast probable prime (Miller-Rabin) ----------------
def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p):
            return p

# ---------------- simple RSA (educational only) ----------------
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1 = egcd(b,a%b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a,m):
    g,x,y = egcd(a,m)
    if g != 1:
        raise Exception('modinv does not exist')
    return x % m

def generate_rsa_keypair(bits=1024):
    e = 65537
    while True:
        p = generate_prime(bits//2)
        q = generate_prime(bits//2)
        if p == q:
            continue
        phi = (p-1)*(q-1)
        if math.gcd(e, phi) == 1:
            break
    n = p*q
    d = modinv(e, phi)
    return (n,e), (n,d)

def rsa_encrypt(pub, m_bytes):
    n,e = pub
    m = int.from_bytes(m_bytes, 'big')
    if m >= n:
        raise ValueError("message too long for RSA modulus (use hybrid envelope)")
    c = pow(m, e, n)
    return c.to_bytes((n.bit_length()+7)//8, 'big')

def rsa_decrypt(priv, c_bytes):
    n,d = priv
    c = int.from_bytes(c_bytes, 'big')
    m = pow(c, d, n)
    return m.to_bytes((m.bit_length()+7)//8, 'big')

def rsa_sign(priv, message_bytes):
    n,d = priv
    h = hashlib.sha256(message_bytes).digest()
    m = int.from_bytes(h, 'big')
    sig = pow(m, d, n)
    return sig.to_bytes((n.bit_length()+7)//8, 'big')

def rsa_verify(pub, message_bytes, signature_bytes):
    n,e = pub
    sig = int.from_bytes(signature_bytes, 'big')
    h_calc = hashlib.sha256(message_bytes).digest()
    m = pow(sig, e, n)
    h_from_sig = m.to_bytes((m.bit_length()+7)//8, 'big')
    return h_from_sig.endswith(h_calc)

# ---------------- Diffie-Hellman ephemeral ----------------
def generate_dh_params(bits=512):
    p = generate_prime(bits)
    g = 2
    return p,g

def dh_priv(p):
    return secrets.randbelow(p-3) + 2

def dh_pub(g, priv, p):
    return pow(g, priv, p)

def dh_shared(pub_other, priv, p):
    return pow(pub_other, priv, p)

# ---------------- symmetric keystream (sha256-ctr XOR) ----------------
def sha256_keystream(key_bytes, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key_bytes + counter.to_bytes(8,'big')).digest())
        counter += 1
    return bytes(out[:length])

def xor_encrypt(key_bytes, plaintext_bytes):
    ks = sha256_keystream(key_bytes, len(plaintext_bytes))
    return bytes(a^b for a,b in zip(plaintext_bytes, ks))

# ---------------- Key Management Service ----------------
class KMS:
    def __init__(self):
        self.registry = {}   # name -> public key (n,e)
        self._privs = {}     # name -> private key (n,d) stored only here for demo (in prod use HSM)
        self.revoked = set()
        self.audit = []      # simple audit log list of dicts

    def register(self, name, pub, priv=None):
        self.registry[name] = pub
        if priv:
            self._privs[name] = priv
        self.audit.append({'op':'register','name':name,'ts':time.time()})
        print(f"[KMS] Registered {name}")

    def get_public(self, name):
        if name in self.revoked:
            raise Exception("Requested entity revoked")
        if name not in self.registry:
            raise Exception("Unknown entity")
        return self.registry[name]

    def revoke(self, name):
        self.revoked.add(name)
        self.audit.append({'op':'revoke','name':name,'ts':time.time()})
        print(f"[KMS] Revoked {name}")

    def is_revoked(self,name):
        return name in self.revoked

    # Demo-only: allow retrieving private (only authorized admin would do this; production uses HSM)
    def _get_private_for_demo(self, name):
        return self._privs.get(name)

# ---------------- Subsystem abstraction ----------------
@dataclass
class Subsystem:
    name: str
    kms: KMS
    rsa_pub: tuple
    rsa_priv: tuple

    @classmethod
    def create(cls, name, kms, rsa_bits=1024):
        pub, priv = generate_rsa_keypair(bits=rsa_bits)
        kms.register(name, pub, priv)
        return cls(name, kms, pub, priv)

    def send_secure(self, recipient_name, document_bytes):
        if self.kms.is_revoked(self.name):
            raise Exception("Sender revoked")
        recipient_pub = self.kms.get_public(recipient_name)

        # create ephemeral DH params
        p,g = generate_dh_params(bits=512)
        a = dh_priv(p)
        A = dh_pub(g,a,p)
        A_bytes = A.to_bytes((p.bit_length()+7)//8,'big')

        # try RSA encrypt A_bytes; if too large do envelope
        try:
            enc_A = rsa_encrypt(recipient_pub, A_bytes)
            envelope = {'type':'rsa', 'enc': enc_A.hex()}
        except ValueError:
            # envelope symmetric key
            Ksym = secrets.token_bytes(32)
            enc_payload = xor_encrypt(Ksym, A_bytes)
            enc_key = rsa_encrypt(recipient_pub, Ksym)
            envelope = {'type':'envelope', 'enc': enc_payload.hex(), 'enc_key': enc_key.hex()}

        # sign document
        signature = rsa_sign(self.rsa_priv, document_bytes)

        package = {
            'from': self.name,
            'envelope': envelope,
            'p': p,
            'g': g,
            'signature': signature.hex(),
            'document': document_bytes.hex(),
            # we return ephemeral a in return for demo finalization only
            'a_demo': a
        }
        self.kms.audit.append({'op':'send','from':self.name,'to':recipient_name,'ts':time.time()})
        return json.dumps(package)

    def receive_secure(self, package_json):
        package = json.loads(package_json)
        sender = package['from']
        if self.kms.is_revoked(self.name) or self.kms.is_revoked(sender):
            raise Exception("Revoked entity involved")

        envelope = package['envelope']
        p = int(package['p'])
        g = int(package['g'])

        # recover A
        if envelope['type'] == 'rsa':
            enc_A = bytes.fromhex(envelope['enc'])
            A_bytes = rsa_decrypt(self.rsa_priv, enc_A)
        else:
            enc_payload = bytes.fromhex(envelope['enc'])
            enc_key = bytes.fromhex(envelope['enc_key'])
            Ksym = rsa_decrypt(self.rsa_priv, enc_key)
            A_bytes = xor_encrypt(Ksym, enc_payload)
        A = int.from_bytes(A_bytes, 'big')

        # compute own DH public and shared secret
        b = dh_priv(p)
        B = dh_pub(g,b,p)
        shared = dh_shared(A, b, p)
        key = hashlib.sha256(shared.to_bytes((p.bit_length()+7)//8,'big')).digest()

        # create response by encrypting document under symmetric key and sending B encrypted under sender's public
        sender_pub = self.kms.get_public(sender)
        B_bytes = B.to_bytes((p.bit_length()+7)//8,'big')
        try:
            enc_B = rsa_encrypt(sender_pub, B_bytes)
            resp_env = {'type':'rsa','enc': enc_B.hex()}
        except ValueError:
            Ksym2 = secrets.token_bytes(32)
            enc_payload2 = xor_encrypt(Ksym2, B_bytes)
            enc_key2 = rsa_encrypt(sender_pub, Ksym2)
            resp_env = {'type':'envelope','enc': enc_payload2.hex(), 'enc_key': enc_key2.hex()}

        document = bytes.fromhex(package['document'])
        signature = bytes.fromhex(package['signature'])
        # verify signature
        if not rsa_verify(sender_pub, document, signature):
            raise Exception("Invalid signature")

        encrypted_doc = xor_encrypt(key, document)
        response = {
            'from': self.name,
            'resp_env': resp_env,
            'encrypted_doc': encrypted_doc.hex(),
            'p': p
        }
        self.kms.audit.append({'op':'receive','from':self.name,'sender':sender,'ts':time.time()})
        return json.dumps(response)

    def finalize(self, response_json, a_private, p):
        response = json.loads(response_json)
        if response['from'] == self.name:
            raise Exception("bad response")

        resp_env = response['resp_env']
        if resp_env['type'] == 'rsa':
            enc_B = bytes.fromhex(resp_env['enc'])
            B_bytes = rsa_decrypt(self.rsa_priv, enc_B)
        else:
            enc_payload = bytes.fromhex(resp_env['enc'])
            enc_key = bytes.fromhex(resp_env['enc_key'])
            Ksym = rsa_decrypt(self.rsa_priv, enc_key)
            B_bytes = xor_encrypt(Ksym, enc_payload)
        B = int.from_bytes(B_bytes, 'big')
        shared = dh_shared(B, a_private, p)
        key = hashlib.sha256(shared.to_bytes((p.bit_length()+7)//8,'big')).digest()
        encrypted_doc = bytes.fromhex(response['encrypted_doc'])
        plaintext = xor_encrypt(key, encrypted_doc)
        return plaintext

# ---------------- Demo run ----------------
def demo():
    kms = KMS()
    # create subsystems
    A = Subsystem.create("Finance", kms, rsa_bits=1024)
    B = Subsystem.create("HR", kms, rsa_bits=1024)
    C = Subsystem.create("SupplyChain", kms, rsa_bits=1024)

    print("Registered:", list(kms.registry.keys()))

    document = b"Quarterly Financial Report: Revenue=10M, Expenses=6M"
    pkg = A.send_secure("HR", document)
    # For demo we use A's 'a_demo' to finalize
    pkg_obj = json.loads(pkg)
    a_demo = pkg_obj['a_demo']
    resp = B.receive_secure(pkg)

    recovered = A.finalize(resp, a_demo, int(pkg_obj['p']))
    print("Recovered plaintext at Finance:", recovered.decode())

    # tamper test - change document in package -> HR rejects signature
    tam = json.loads(A.send_secure("HR", b"Original"))
    tam['document'] = b"Tampered".hex()
    try:
        B.receive_secure(json.dumps(tam))
    except Exception as e:
        print("Tamper detected:", e)

    # revocation demo
    kms.revoke("Finance")
    try:
        A.send_secure("HR", document)
    except Exception as e:
        print("Blocked after revocation:", e)

    # scalability: add new subsystem
    New = Subsystem.create("Legal", kms, rsa_bits=1024)
    print("Now registered:", list(kms.registry.keys()))
    print("Audit log entries:", len(kms.audit))

if __name__ == "__main__":
    demo()
