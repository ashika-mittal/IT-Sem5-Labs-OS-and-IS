from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# Input message and key
message = "Encryption Strength"
key_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)

# Generate a random IV (Initialization Vector)
iv = bytes.fromhex('00112233445566778899aabbccddeeff')  # or os.urandom(16)

# Create AES cipher for encryption
cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)

# Pad message and encrypt
ciphertext = cipher_encrypt.encrypt(pad(message.encode(), AES.block_size))

print("Encrypted (Hex):", ciphertext.hex())

# Decrypt to verify
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
decrypted_message = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)

print("Decrypted message:", decrypted_message.decode())
