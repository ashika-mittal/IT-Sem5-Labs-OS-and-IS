from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048) #pvt
public_key = key.publickey() #public
cipher = PKCS1_OAEP.new(public_key)
message = b"Asymmetric Encryption"
ciphertext = cipher.encrypt(message)
print(ciphertext.hex())

decipher = PKCS1_OAEP.new(key)
plaintext = decipher.decrypt(ciphertext)
print(plaintext.decode())
