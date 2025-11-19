import socket, pickle, math, random
from Crypto.Util.number import inverse

# ==============================
# --- CRYPTO FUNCTIONS ---
# ==============================

def lcm(a,b): return a*b//math.gcd(a,b)

# ----- ElGamal -----
def elgamal_decrypt(priv, ct):
    p,g,x = priv
    c1,c2 = ct
    s = pow(c1,x,p)
    s_inv = inverse(s,p)
    return (c2*s_inv)%p

def elgamal_homomorphic_mul(c1, c2, p):
    return ((c1[0]*c2[0])%p, (c1[1]*c2[1])%p)

# ----- Paillier -----
def paillier_decrypt(pub, priv, c):
    n,g = pub; lam,mu = priv
    nsq = n*n
    def L(u): return (u-1)//n
    return (L(pow(c,lam,nsq))*mu)%n

def paillier_homomorphic_add(pub, c1, c2):
    n,g = pub; return (c1*c2)%(n*n)

# ==============================
# --- MAIN SERVER CODE ---
# ==============================

HOST = '127.0.0.1'
PORT = 65432

s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
print("🔐 Server ready. Listening on port", PORT)

conn, addr = s.accept()
print("💡 Connected by", addr)

data = b''
while True:
    chunk = conn.recv(4096)
    if not chunk: break
    data += chunk
conn.close()

import pickle
payload = pickle.loads(data)

mode = payload["mode"]

if mode == "elgamal":
    pub, priv, c1, c2 = payload["pub"], payload["priv"], payload["c1"], payload["c2"]
    print("\n--- ElGamal Homomorphic Multiplication ---")
    c_mul = elgamal_homomorphic_mul(c1, c2, pub[0])
    dec = elgamal_decrypt(priv, c_mul)
    print("Ciphertext 1:", c1)
    print("\nCiphertext 2:", c2)
    print("\nDecrypted Product:", dec)

elif mode == "paillier":
    pub, priv, c1, c2 = payload["pub"], payload["priv"], payload["c1"], payload["c2"]
    print("\n--- Paillier Homomorphic Addition ---")
    c_sum = paillier_homomorphic_add(pub, c1, c2)
    dec_sum = paillier_decrypt(pub, priv, c_sum)
    print("Ciphertext 1:", c1)
    print("Ciphertext 2:", c2)
    print("Decrypted Sum:", dec_sum)
