from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

# Key and IV (both must be 8 bytes for DES)
key = b"A1B2C3D4"
iv = b"12345678"

# Message to encrypt
message = b"Secure Communication"

# Pad the message to multiple of DES block size (8 bytes)
padded_message = pad(message, DES.block_size)

# Create DES cipher in CBC mode
cipher = DES.new(key, DES.MODE_CBC, iv)

# Encrypt the message
ciphertext = cipher.encrypt(padded_message)

# Print ciphertext as hex
print("Ciphertext (hex):", hexlify(ciphertext).decode())

# Now decrypt
decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_padded = decipher.decrypt(ciphertext)

# Remove padding
decrypted_message = unpad(decrypted_padded, DES.block_size)

# Print the decrypted message
print("Decrypted message:", decrypted_message.decode())
