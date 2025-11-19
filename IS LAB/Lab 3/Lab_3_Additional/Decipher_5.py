import time, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def rsa_test(msg):
    key = RSA.generate(2048)
    cipher_enc = PKCS1_OAEP.new(key.publickey())
    cipher_dec = PKCS1_OAEP.new(key)
    start = time.time(); ct = cipher_enc.encrypt(msg); enc = time.time() - start
    start = time.time(); pt = cipher_dec.decrypt(ct); dec = time.time() - start
    return enc, dec

def ecc_elgamal_test(msg):
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = eph_priv.exchange(ec.ECDH(), pub)
    key = HKDF(hashes.SHA256(), 32, None, b'handshake data', default_backend()).derive(shared_key)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
    padder = padding.PKCS7(128).padder()
    data = padder.update(msg) + padder.finalize()
    enc_obj = cipher.encryptor()
    start = time.time(); ct = enc_obj.update(data) + enc_obj.finalize(); enc = time.time() - start
    cipher_dec = Cipher(algorithms.AES(key), modes.GCM(iv, enc_obj.tag), default_backend())
    unpadder = padding.PKCS7(128).unpadder()
    dec_obj = cipher_dec.decryptor()
    start = time.time(); pt = dec_obj.update(ct) + dec_obj.finalize(); dec = time.time() - start
    pt = unpadder.update(pt) + unpadder.finalize()
    return enc, dec

msgs = [b'a'*1024, b'a'*10240]

print("RSA (1KB, 10KB):")
for m in msgs:
    e, d = rsa_test(m)
    print(f"Enc: {e:.4f}s, Dec: {d:.4f}s")

print("\nECC ElGamal-like (1KB, 10KB):")
for m in msgs:
    e, d = ecc_elgamal_test(m)
    print(f"Enc: {e:.4f}s, Dec: {d:.4f}s")
