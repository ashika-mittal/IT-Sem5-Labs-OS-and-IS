from Crypto.Util.number import inverse
from Crypto.Random.random import randint

# Given keys
p = 7919
g = 2
x = 2999  # private key
h = pow(g, x, p)  # public key component

# Message
message_str = "Asymmetric Algorithms"
message_bytes = message_str.encode('utf-8')
message_int = int.from_bytes(message_bytes, 'big')

# Encryption
k = randint(1, p - 2)  # random integer
c1 = pow(g, k, p)
s = pow(h, k, p)
c2 = (message_int * s) % p

print("Encrypted ciphertext (c1, c2):", (c1, c2))

# Decryption
s_dec = pow(c1, x, p)
s_inv = inverse(s_dec, p)
message_decrypted_int = (c2 * s_inv) % p

# Convert decrypted integer back to string
dec_len = (message_decrypted_int.bit_length() + 7) // 8
message_decrypted_bytes = message_decrypted_int.to_bytes(dec_len, 'big')
message_decrypted_str = message_decrypted_bytes.decode('utf-8')

print("Decrypted message:", message_decrypted_str)
