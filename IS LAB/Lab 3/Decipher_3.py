import random

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    return result

def text_to_int(text):
    return int.from_bytes(text.encode(), 'big')

def int_to_text(number):
    length = (number.bit_length() + 7) // 8
    return number.to_bytes(length, 'big').decode()

p = 6277101735386680763835789423207666416102355444464034512895
g = 2
x = 123456789
h = mod_exp(g, x, p)

message = "Confidential Data"
m_int = text_to_int(message)
if m_int >= p:
    raise ValueError("Message too large for key size")

k = random.randint(2, p-2)
c1 = mod_exp(g, k, p)
s = mod_exp(h, k, p)
c2 = (m_int * s) % p

shared_secret = mod_exp(c1, x, p)
s_inv = pow(shared_secret, -1, p)
decrypted_int = (c2 * s_inv) % p
plaintext = int_to_text(decrypted_int)

print("Ciphertext:", (c1, c2))
print("Decrypted Plaintext:", plaintext)
