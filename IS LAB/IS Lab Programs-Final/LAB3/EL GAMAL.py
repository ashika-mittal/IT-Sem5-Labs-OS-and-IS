import random
import math
from Crypto.Util.number import getPrime

# Encrypt the message
def encrypt(message, q, h, g):
    k = random.randint(1, q-2)  # Sender's ephemeral key
    s = pow(h, k, q)  # Shared secret
    p = pow(g, k, q)  # Cipher component
    encrypted = [s * ord(char) for char in message]
    print("g^k used:", p)
    print("h^k used:", s)
    return encrypted, p

# Decrypt the message
def decrypt(encrypted, p, x, q):
    s = pow(p, x, q)  # Shared secret
    decrypted = [chr(int(c // s)) for c in encrypted]
    return ''.join(decrypted)

# Main flow
message = "Confidential Data"
print("Original Message:", message)

q = getPrime(256)  # Generates a 256-bit prime number
g = random.randint(2, q)            # Generator
x = random.randint(1,q-2)           # Receiver's private key
h = pow(g, x, q)                    # Receiver's public key

print("g used:", g)
print("h = g^x mod q:", h)

encrypted_msg, p = encrypt(message, q, h, g)
decrypted_msg = decrypt(encrypted_msg, p, x, q)

print("Decrypted Message:", decrypted_msg)
