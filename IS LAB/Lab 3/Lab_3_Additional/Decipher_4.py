from Crypto.Util import number
from Crypto.Random import get_random_bytes

# Keys: prime p, generator g, private key x, public key y
p = 7919
g = 2
x = 2999  # private key
y = pow(g, x, p)  # public key

def encrypt(public_key, plaintext):
    p, g, y = public_key
    k = number.getRandomRange(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (plaintext * pow(y, k, p)) % p
    return (c1, c2)

def decrypt(private_key, ciphertext):
    p, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = number.inverse(s, p)
    return (c2 * s_inv) % p

# Convert message to integer
message = "Asymmetric Algorithms"
message_int = int.from_bytes(message.encode(), 'big')

# Encrypt & decrypt
cipher = encrypt((p, g, y), message_int)
decrypted_int = decrypt((p, x), cipher)
decrypted_msg = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()

print("Encrypted:", cipher)
print("Decrypted:", decrypted_msg)
