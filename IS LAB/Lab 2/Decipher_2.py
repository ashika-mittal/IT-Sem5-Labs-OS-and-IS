from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
message = b"Sensitive Information"

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message, AES.block_size))

decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)

print(ciphertext.hex())
print(plaintext.decode())
