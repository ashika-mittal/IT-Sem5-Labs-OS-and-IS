from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# Valid 24-byte key: three different 8-byte keys concatenated
key_hex = "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"
key = DES3.adjust_key_parity(unhexlify(key_hex))
message = b"Classified Text"

cipher = DES3.new(key, DES3.MODE_ECB)
ciphertext = cipher.encrypt(pad(message, DES3.block_size))

decipher = DES3.new(key, DES3.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), DES3.block_size)

print(ciphertext.hex())
print(plaintext.decode())
