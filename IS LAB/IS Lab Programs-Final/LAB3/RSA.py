from sympy import mod_inverse
import math
p,q = 61,53
n = p * q
phi_n = (p - 1) * (q - 1)
e=3
while math.gcd(e,phi_n)!=1:
    e+=2
d = mod_inverse(e,phi_n)
print(d)
# RSA encryption function
def rsa_encrypt(message, n, e):
    encmsg=[]
    for char in message:
        encmsg.append((pow(ord(char),e,n)))
    return encmsg

# RSA decryption function
def rsa_decrypt(encrypted_int, n, d):
    decmsg=""
    for i in encrypted_int:
        decmsg += chr(pow(i,d,n))

    return decmsg

# Example message
message = "Asymmetric Encryption"

# Encrypt the message
encrypted_message = rsa_encrypt(message, n, e)
print("Encrypted message (integer):", encrypted_message)

# Decrypt the message
decrypted_message = rsa_decrypt(encrypted_message, n, d)
print("Decrypted message:", decrypted_message)