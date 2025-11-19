#!/usr/bin/env python3
import socket, json, hashlib, random
from math import gcd
from Crypto.Util.number import getPrime

# === Helpers ===
def sha256_hex(msg): return hashlib.sha256(msg).hexdigest()
def sha256_bytes(msg): return hashlib.sha256(msg).digest()
def sha256_int_mod(mbytes, mod):
    return int.from_bytes(hashlib.sha256(mbytes).digest(),'big') % mod
def lcm(a,b): return a//gcd(a,b)*b

# === Paillier encrypt ===
def paillier_encrypt(pub,m):
    n,g=pub; nsq=n*n
    while True:
        r=random.randrange(1,n)
        if gcd(r,n)==1: break
    return (pow(g,m,nsq)*pow(r,n,nsq))%nsq

# === ElGamal sign ===
def elgamal_sign(priv,msg):
    p,g,x=priv; H=sha256_int_mod(msg,p-1)
    while True:
        k=random.randrange(2,p-2)
        if gcd(k,p-1)==1: break
    r=pow(g,k,p)
    s=(pow(k,-1,p-1)*(H - x*r))%(p-1)
    return (r,s)

def run_client(server_host='127.0.0.1',port=65432):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((server_host,port))
    print("Connected to server, waiting for public keys...")

    data=b''
    while b"<<ENDKEYS>>" not in data:
        data+=s.recv(8192)
    parts=data.split(b"<<ENDKEYS>>")
    pub_data=json.loads(parts[0].decode())
    paillier_pub=tuple(pub_data['paillier_pub'])
    elg_pub=tuple(pub_data['elgamal_pub'])
    print("🔑 Public keys received.")

    rec=input("\nEnter hospital record text: ")
    val=int(input("Enter numeric value (e.g., patient count): "))

    # Derive a private key for signing (in real world, hospital has its own key)
    p,g,y=elg_pub
    x=random.randrange(2,p-2)
    elg_priv=(p,g,x)

    hash_hex=sha256_hex(rec.encode())
    sig=elgamal_sign(elg_priv,sha256_bytes(rec.encode()))
    c=paillier_encrypt(paillier_pub,val)

    payload={'record_text':rec,'hash_hex':hash_hex,'signature':sig,'paillier_cipher':c}
    s.sendall(json.dumps(payload).encode())
    print("\nData sent to server successfully.")
    s.close()

if __name__=="__main__":
    run_client()
