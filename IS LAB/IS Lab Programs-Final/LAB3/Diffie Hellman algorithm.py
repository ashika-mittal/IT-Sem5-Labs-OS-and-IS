import os, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AES encryption/decryption
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    return iv + cipher.encryptor().update(data)

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    return cipher.decryptor().update(encrypted_data[16:])

# RSA key generation
def generate_rsa_keys():
    start = time.time()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key(), time.time() - start

# ECC key generation (ElGamal-like)
def generate_ecc_keys():
    start = time.time()
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key(), time.time() - start

# RSA encrypt/decrypt AES key
def rsa_encrypt_key(key, pub):
    return pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_key(enc_key, priv):
    return priv.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# ECC encrypt/decrypt AES key using ECDH
def ecc_encrypt_key(key, sender_priv, receiver_pub):
    shared = sender_priv.exchange(ec.ECDH(), receiver_pub)
    derived = HKDF(hashes.SHA256(), 32, None, b'ecdh', default_backend()).derive(shared)
    return aes_encrypt(key, derived)

def ecc_decrypt_key(enc_key, receiver_priv, sender_pub):
    shared = receiver_priv.exchange(ec.ECDH(), sender_pub)
    derived = HKDF(hashes.SHA256(), 32, None, b'ecdh', default_backend()).derive(shared)
    return aes_decrypt(enc_key, derived)

# Benchmarking
def benchmark(message_size_kb):
    message = os.urandom(message_size_kb * 1024)
    aes_key = os.urandom(32)

    # RSA
    rsa_priv, rsa_pub, rsa_keygen_time = generate_rsa_keys()
    start = time.time()
    rsa_enc_key = rsa_encrypt_key(aes_key, rsa_pub)
    rsa_dec_key = rsa_decrypt_key(rsa_enc_key, rsa_priv)
    rsa_enc_msg = aes_encrypt(message, rsa_dec_key)
    rsa_dec_msg = aes_decrypt(rsa_enc_msg, rsa_dec_key)
    rsa_total_time = time.time() - start

    # ECC (ElGamal-like)
    ecc_priv_sender, ecc_pub_sender, ecc_keygen_time = generate_ecc_keys()
    ecc_priv_receiver, ecc_pub_receiver, _ = generate_ecc_keys()
    start = time.time()
    ecc_enc_key = ecc_encrypt_key(aes_key, ecc_priv_sender, ecc_pub_receiver)
    ecc_dec_key = ecc_decrypt_key(ecc_enc_key, ecc_priv_receiver, ecc_pub_sender)
    ecc_enc_msg = aes_encrypt(message, ecc_dec_key)
    ecc_dec_msg = aes_decrypt(ecc_enc_msg, ecc_dec_key)
    ecc_total_time = time.time() - start

    print(f"\n📦 Message Size: {message_size_kb} KB")
    print(f"🔐 RSA - KeyGen: {rsa_keygen_time:.4f}s | Total: {rsa_total_time:.4f}s")
    print(f"🔐 ECC - KeyGen: {ecc_keygen_time:.4f}s | Total: {ecc_total_time:.4f}s")

# Run benchmarks
benchmark(1)
benchmark(10)
