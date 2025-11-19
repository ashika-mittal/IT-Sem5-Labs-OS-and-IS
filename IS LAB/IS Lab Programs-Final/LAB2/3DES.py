from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Use a secure 24-byte key with distinct segments
key = b"12345678ABCDEFGH87654321"  # 3 distinct 8-byte keys
message = b"Classified Text"

# Create cipher object
cipher = DES3.new(key, DES3.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(pad(message, DES3.block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
print("Decrypted message:", decrypted.decode())

#DES: 56-bit key (8 bytes stored)
#3DES: 112-bit (16 bytes, 2 keys) or 168-bit (24 bytes, 3 keys)
