import socket, random, math
from Crypto.Util.number import getPrime, inverse

# ==============================
# --- CRYPTO FUNCTIONS ---
# ==============================

def lcm(a,b): return a*b//math.gcd(a,b)

# ----- ElGamal -----
def elgamal_keygen(bits=512):
    p = getPrime(bits)
    g = 2
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    pub, priv = (p,g,y), (p,g,x)
    return pub, priv

def elgamal_encrypt(pub, m):
    p,g,y = pub
    k = random.randrange(2, p-2)
    c1 = pow(g,k,p)
    c2 = (m * pow(y,k,p)) % p
    return (c1,c2)

# ----- Paillier -----
def paillier_keygen(bits=512):
    p = getPrime(bits//2); q = getPrime(bits//2)
    n = p*q; g = n+1
    lam = lcm(p-1,q-1)
    def L(u): return (u-1)//n
    mu = inverse(L(pow(g,lam,n*n)), n)
    return (n,g),(lam,mu)

def paillier_encrypt(pub,m):
    n,g = pub; nsq=n*n
    while True:
        r = random.randrange(1,n)
        if math.gcd(r,n)==1: break
    return (pow(g,m,nsq)*pow(r,n,nsq))%nsq

# ==============================
# --- MAIN CLIENT CODE ---
# ==============================

MODE = "elgamal"   # change to "paillier" for Paillier demo

HOST = '127.0.0.1'
PORT = 65432

s = socket.socket()
s.connect((HOST, PORT))

MODE = input("Enter mode (elgamal/paillier): ")

if MODE == "elgamal":
    pub, priv = elgamal_keygen()
    a1=int(input("Enter the first integer: "))
    a2=int(input("Enter the second integer: "))
    c1 = elgamal_encrypt(pub, a1)
    c2 = elgamal_encrypt(pub, a2)
    data = {"mode": "elgamal", "pub": pub, "priv": priv, "c1": c1, "c2": c2}
elif MODE == "paillier":
    pub, priv = paillier_keygen()
    #m1, m2 = 15, 25
    b1=int(input("Enter the first integer: "))
    b2=int(input("Enter the second integer: "))
    c1 = paillier_encrypt(pub, b1)
    c2 = paillier_encrypt(pub,b2)
    data = {"mode": "paillier", "pub": pub, "priv": priv, "c1": c1, "c2": c2}

import pickle
payload = pickle.dumps(data)
s.sendall(payload)
print("✅ Data sent to server.")
s.close()
