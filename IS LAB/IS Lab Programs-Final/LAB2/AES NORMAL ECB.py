from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

msg=b"Information Security"
key=bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

padded_msg=pad(msg,AES.block_size)
cipher=AES.new(key,AES.MODE_ECB)
ciphertext=cipher.encrypt(padded_msg)
print(ciphertext.hex())

decrypt=cipher.decrypt(ciphertext)
unpadded_msg=unpad(decrypt,AES.block_size)
print(unpadded_msg.decode())
#just change key for AES 128,256
#msg = aff_enc.encode() TO CONVERT ANY VARIABLE NAMED AFF_ENC TO BYTES WHICH IS REQUIRED FOR AES