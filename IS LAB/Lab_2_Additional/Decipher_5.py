from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

# Inputs
key_hex = "0123456789ABCDEF0123456789ABCDEF"
nonce_hex = "0000000000000000"
message = "Cryptography Lab Exercise"

# Convert hex to bytes
key = bytes.fromhex(key_hex)
nonce = bytes.fromhex(nonce_hex)

# Create counter object (nonce + initial counter)
ctr = Counter.new(64, prefix=nonce, initial_value=0)

# Create AES cipher in CTR mode
cipher_encrypt = AES.new(key, AES.MODE_CTR, counter=ctr)

# Encrypt message
ciphertext = cipher_encrypt.encrypt(message.encode())
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt using same key and nonce
ctr_dec = Counter.new(64, prefix=nonce, initial_value=0)
cipher_decrypt = AES.new(key, AES.MODE_CTR, counter=ctr_dec)
decrypted = cipher_decrypt.decrypt(ciphertext)

print("Decrypted message:", decrypted.decode())
