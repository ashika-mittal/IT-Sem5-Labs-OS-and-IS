# client_simple.py
# Minimal client: canonicalize -> hash -> Affine encrypt -> RSA sign -> ADD.
# For SEARCH: encrypt keyword with Affine, ask server, then decrypt + verify locally.
import socket, json, re, hashlib
from Crypto.Util.number import getPrime, inverse

HOST, PORT = "127.0.0.1", 50555

# ---------- Canonicalization + Hash ----------
def canon(s):  # SAME string used for hash/sign/encrypt/verify
    return re.sub(r"[^A-Za-z]", "", s).lower()

def digest_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()  # change to sha1/md5 if asked

# ---------- Affine (deterministic for searchable enc) ----------
def egcd(a, b):
    if b == 0: return (1,0,a)
    x,y,g = 0,1,b; u,v,w = 1,0,a
    while w:
        q = g//w; x,u = u, x-q*u; y,v = v, y-q*v; g,w = w, g-q*w
    return (x,y,g)

def modinv(a, m):
    a%=m; x,y,g = egcd(a,m)
    if g!=1: raise ValueError("no inverse")
    return x % m

def affine_encrypt(txt, a, b):
    assert egcd(a,26)[2]==1, "a must be coprime with 26"
    return "".join(chr(((a*(ord(ch)-97)+b)%26)+97) for ch in txt if "a"<=ch<="z")

def affine_decrypt(ct, a, b):
    a_inv = modinv(a,26)
    return "".join(chr(((a_inv*((ord(ch)-97)-b))%26)+97) for ch in ct if "a"<=ch<="z")

A,B = 7,3  # keep gcd(A,26)=1

# ---------- RSA (textbook) ----------
def rsa_keygen(bits=1024):
    p,q = getPrime(bits//2), getPrime(bits//2)
    n = p*q; phi = (p-1)*(q-1); e=65537; d = inverse(e, phi)
    return {"n":n,"e":e}, {"n":n,"d":d}

def rsa_sign(msg, priv):
    n,d = priv["n"], priv["d"]
    h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
    return pow(h, d, n)

def rsa_verify(msg, sig, pub):
    n,e = pub["n"], pub["e"]
    h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % n
    return pow(sig, e, n) == h

PUB, PRIV = rsa_keygen()

# ---------- Tiny TCP helper ----------
def send(obj):
    with socket.socket() as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(obj).encode())
        return json.loads(s.recv(65535).decode())

# ---------- Simple demo flow ----------
def add_record(name, disease, treatment):
    plain = canon(f"{name}-{disease}-{treatment}")
    h = digest_hex(plain)
    ct = affine_encrypt(plain, A, B)
    sig = rsa_sign(plain, PRIV)
    resp = send({"op":"ADD", "cipher":ct, "hash":h, "sig":sig, "pub":PUB})
    print("\n[ADD]")
    print("  canonical:", plain)
    print("  hash     :", h)
    print("  cipher   :", ct)
    print("  signature:", sig)
    print("  server   :", resp)

def search(keyword):
    enc_kw = affine_encrypt(canon(keyword), A, B)
    resp = send({"op":"SEARCH", "enc_kw": enc_kw})
    print(f"\n[SEARCH] keyword='{keyword}'  enc_kw='{enc_kw}'")
    for i, r in enumerate(resp.get("matches", []), 1):
        dec = affine_decrypt(r["cipher"], A, B)
        ok_sig  = rsa_verify(dec, r["sig"], r["pub"])
        ok_hash = (digest_hex(dec) == r["hash"])
        print(f"  match#{i}:")
        print(f"    cipher : {r['cipher']}")
        print(f"    decrypt: {dec}")
        print(f"    sig_ok : {'✅' if ok_sig else '❌'}   hash_ok: {'✅' if ok_hash else '❌'}")

if __name__ == "__main__":
    print("[client] demo run -> add 2, then search 'Covid'")
    add_record("Amit", "Covid", "Remdesivir")
    add_record("Riya", "Malaria", "Paracetamol")
    search("Covid")