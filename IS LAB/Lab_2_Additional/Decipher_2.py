from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Convert hex key and blocks to bytes
key = bytes.fromhex('A1B2C3D4E5F60708')
block1_hex = '54686973206973206120636f6e666964656e7469616c206d657373616765'
block2_hex = '416e64207468697320697320746865207365636f6e6420626c6f636b'

block1_bytes = bytes.fromhex(block1_hex)
block2_bytes = bytes.fromhex(block2_hex)

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Pad blocks to multiple of 8 bytes
block1_padded = pad(block1_bytes, DES.block_size)
block2_padded = pad(block2_bytes, DES.block_size)

# Encrypt blocks
ciphertext_block1 = cipher.encrypt(block1_padded)
ciphertext_block2 = cipher.encrypt(block2_padded)

print("a. Ciphertext for Block 1 (hex):", ciphertext_block1.hex())
print("a. Ciphertext for Block 2 (hex):", ciphertext_block2.hex())

# Decrypt blocks
plaintext_block1_padded = cipher.decrypt(ciphertext_block1)
plaintext_block2_padded = cipher.decrypt(ciphertext_block2)

# Unpad plaintext
plaintext_block1 = unpad(plaintext_block1_padded, DES.block_size)
plaintext_block2 = unpad(plaintext_block2_padded, DES.block_size)

print("\nb. Decrypted Plaintext for Block 1:", plaintext_block1.decode('utf-8'))
print("b. Decrypted Plaintext for Block 2:", plaintext_block2.decode('utf-8'))
