from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Step 1: Generate ECC private and public keys
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Step 2: Simulate sender generating ephemeral key and shared secret
ephemeral_private = ec.generate_private_key(ec.SECP256R1())
shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

# Step 3: Derive AES key from shared secret
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_secret)

# Step 4: Encrypt the message using AES
message = b"Secure Transactions"
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()

# Step 5: Send ciphertext and ephemeral public key
ephemeral_public = ephemeral_private.public_key()

# Step 6: Receiver derives shared secret using their private key
shared_secret_receiver = private_key.exchange(ec.ECDH(), ephemeral_public)

# Step 7: Derive AES key again
aes_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_secret_receiver)

# Step 8: Decrypt the ciphertext
cipher = Cipher(algorithms.AES(aes_key_receiver), modes.CFB(iv))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

# Output
print("Ciphertext:", ciphertext.hex())
print("Decrypted:", decrypted_message.decode())
