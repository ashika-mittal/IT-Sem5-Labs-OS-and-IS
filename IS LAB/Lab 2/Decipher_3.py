import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

message = b"Performance Testing of Encryption Algorithms"
des_key = b"A1B2C3D4"
aes_key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

# DES
des_cipher = DES.new(des_key, DES.MODE_ECB)
start_enc_des = time.time()
des_ciphertext = des_cipher.encrypt(pad(message, DES.block_size))
end_enc_des = time.time()

des_decipher = DES.new(des_key, DES.MODE_ECB)
start_dec_des = time.time()
des_plaintext = unpad(des_decipher.decrypt(des_ciphertext), DES.block_size)
end_dec_des = time.time()

# AES-256
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
start_enc_aes = time.time()
aes_ciphertext = aes_cipher.encrypt(pad(message, AES.block_size))
end_enc_aes = time.time()

aes_decipher = AES.new(aes_key, AES.MODE_ECB)
start_dec_aes = time.time()
aes_plaintext = unpad(aes_decipher.decrypt(aes_ciphertext), AES.block_size)
end_dec_aes = time.time()

print("DES Encryption Time:", end_enc_des - start_enc_des)
print("DES Decryption Time:", end_dec_des - start_dec_des)
print("AES-256 Encryption Time:", end_enc_aes - start_enc_aes)
print("AES-256 Decryption Time:", end_dec_aes - start_dec_aes)
