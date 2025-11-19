import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

message = b"Data"

# RSA
start = time.time()
rsa_key = RSA.generate(2048)
end = time.time()
print("RSA Key Gen:", end - start)
rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
start = time.time()
enc_rsa = rsa_cipher.encrypt(message)
end = time.time()
print("RSA Encrypt:", end - start)
rsa_decipher = PKCS1_OAEP.new(rsa_key)
start = time.time()
dec_rsa = rsa_decipher.decrypt(enc_rsa)
end = time.time()
print("RSA Decrypt:", end - start)

# ECC
start = time.time()
ecc_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
end = time.time()
print("ECC Key Gen:", end - start)
shared_key = ecc_key.exchange(ec.ECDH(), ecc_key.public_key())
derived = HKDF(hashes.SHA256(), 32, None, b'handshake', default_backend()).derive(shared_key)
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(derived), modes.GCM(iv), default_backend())
enc_ecc = cipher.encryptor().update(message) + cipher.encryptor().finalize()
print("ECC Encrypt: done")
