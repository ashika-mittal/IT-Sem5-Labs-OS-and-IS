from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key_hex = "FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(key_hex)
message = b"Top Secret Data"

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message, AES.block_size))

decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)

print(ciphertext.hex())
print(plaintext.decode())
