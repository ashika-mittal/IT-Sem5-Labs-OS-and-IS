from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"A1B2C3D4"
message = b"Confidential Data"

cipher = DES.new(key, DES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message, DES.block_size))

decipher = DES.new(key, DES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size)

print(ciphertext.hex())
print(plaintext.decode())
