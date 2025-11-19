from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify

# Use the first 8 bytes (64 bits) from the key for DES
key = b"A1B2C3D4"  # Truncate to 8 bytes

# Data blocks in hex format
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

# Convert hex strings to bytes
block1 = unhexlify(block1_hex)
block2 = unhexlify(block2_hex)

# Pad data to make it a multiple of DES block size (8 bytes)
block1_padded = pad(block1, DES.block_size)
block2_padded = pad(block2, DES.block_size)

# Encrypt using DES in ECB mode
cipher = DES.new(key, DES.MODE_ECB)
ciphertext1 = cipher.encrypt(block1_padded)
ciphertext2 = cipher.encrypt(block2_padded)

# Decrypt ciphertexts
decipher = DES.new(key, DES.MODE_ECB)
decrypted1 = unpad(decipher.decrypt(ciphertext1), DES.block_size)
decrypted2 = unpad(decipher.decrypt(ciphertext2), DES.block_size)

# Print results
print("Ciphertext Block 1 (hex):", hexlify(ciphertext1).decode())
print("Ciphertext Block 2 (hex):", hexlify(ciphertext2).decode())
print("Decrypted Block 1:", decrypted1.decode())
print("Decrypted Block 2:", decrypted2.decode())
