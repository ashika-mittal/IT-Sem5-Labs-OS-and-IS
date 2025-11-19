from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

msg = b"Information Security"
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # AES-128 key

# Generate a random IV (16 bytes)
iv = os.urandom(16)

# Encryption
padded_msg = pad(msg, AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_msg)
print("Ciphertext (hex):", ciphertext.hex())
print("IV (hex):", iv.hex())

# Decryption (must use same IV!)
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = decipher.decrypt(ciphertext)
unpadded_msg = unpad(decrypted, AES.block_size)
print("Decrypted:", unpadded_msg.decode())

#TO RANDOMLY GENERATE KEYS
# Generate a random AES key (16 bytes = 128-bit key)
#key = os.urandom(16)   # For AES-128
# If you want AES-192 -> os.urandom(24)
# If you want AES-256 -> os.urandom(32)