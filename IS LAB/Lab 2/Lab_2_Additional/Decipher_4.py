from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Given key and IV
key_hex = "A1B2C3D4"
iv_str = "12345678"
message = "Secure Communication"

key = bytes.fromhex(key_hex)
iv = iv_str.encode()

# Make sure key is 8 bytes for DES
if len(key) != 8:
    raise ValueError("DES key must be 8 bytes")

# Create cipher object for encryption
cipher_encrypt = DES.new(key, DES.MODE_CBC, iv)

# Pad message to block size and encrypt
padded_msg = pad(message.encode(), DES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_msg)

print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext
cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
# Remove padding to get original message
decrypted_msg = unpad(decrypted_padded, DES.block_size).decode()

print("Decrypted message:", decrypted_msg)
