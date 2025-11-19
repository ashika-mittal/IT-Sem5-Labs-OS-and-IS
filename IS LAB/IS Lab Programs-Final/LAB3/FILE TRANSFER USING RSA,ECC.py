import os, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate AES key
def generate_aes_key():
    return os.urandom(32)  # 256-bit key

# AES Encrypt/Decrypt
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

# RSA Key Generation
def generate_rsa_keys():
    start = time.time()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elapsed = time.time() - start
    return private_key, private_key.public_key(), elapsed

# ECC Key Generation
def generate_ecc_keys():
    start = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1())
    elapsed = time.time() - start
    return private_key, private_key.public_key(), elapsed

# RSA Encrypt/Decrypt AES key
def rsa_encrypt_key(key, public_key):
    return public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_key(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# ECC Encrypt/Decrypt AES key using ECDH
def ecc_encrypt_key(key, sender_private, receiver_public):
    shared = sender_private.exchange(ec.ECDH(), receiver_public)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecdh').derive(shared)
    return aes_encrypt(key, derived)

def ecc_decrypt_key(encrypted_key, receiver_private, sender_public):
    shared = receiver_private.exchange(ec.ECDH(), sender_public)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'ecdh').derive(shared)
    return aes_decrypt(encrypted_key, derived)

# Benchmark
def benchmark(file_size_mb):
    data = os.urandom(file_size_mb * 1024 * 1024)
    aes_key = generate_aes_key()

    # RSA
    rsa_priv, rsa_pub, rsa_keygen_time = generate_rsa_keys()
    start = time.time()
    rsa_enc_key = rsa_encrypt_key(aes_key, rsa_pub)
    rsa_dec_key = rsa_decrypt_key(rsa_enc_key, rsa_priv)
    rsa_enc_data = aes_encrypt(data, rsa_dec_key)
    rsa_dec_data = aes_decrypt(rsa_enc_data, rsa_dec_key)
    rsa_total_time = time.time() - start

    # ECC
    ecc_priv_sender, ecc_pub_sender, ecc_keygen_time = generate_ecc_keys()
    ecc_priv_receiver, ecc_pub_receiver, _ = generate_ecc_keys()
    start = time.time()
    ecc_enc_key = ecc_encrypt_key(aes_key, ecc_priv_sender, ecc_pub_receiver)
    ecc_dec_key = ecc_decrypt_key(ecc_enc_key, ecc_priv_receiver, ecc_pub_sender)
    ecc_enc_data = aes_encrypt(data, ecc_dec_key)
    ecc_dec_data = aes_decrypt(ecc_enc_data, ecc_dec_key)
    ecc_total_time = time.time() - start

    print(f"\n📁 File Size: {file_size_mb} MB")
    print(f"🔐 RSA KeyGen Time: {rsa_keygen_time:.4f}s | Total Time: {rsa_total_time:.4f}s")
    print(f"🔐 ECC KeyGen Time: {ecc_keygen_time:.4f}s | Total Time: {ecc_total_time:.4f}s")

# Run for 1MB and 10MB
benchmark(1)
benchmark(10)
