from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad

msg=b"Confidential Data"
key=b"A1B2C3D4"
padded_msg=pad(msg,DES.block_size)
cipher=DES.new(key,DES.MODE_ECB)
ciphertext=cipher.encrypt(padded_msg)
print(ciphertext.hex())
decrypt=cipher.decrypt(ciphertext)
decrypted_msg=unpad(decrypt,DES.block_size)
print(decrypted_msg.decode())

#DES: 56-bit key (8 bytes stored)
#3DES: 112-bit (16 bytes, 2 keys) or 168-bit (24 bytes, 3 keys)