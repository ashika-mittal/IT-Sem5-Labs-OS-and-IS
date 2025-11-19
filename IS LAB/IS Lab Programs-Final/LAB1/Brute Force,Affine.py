cipher = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

from math import gcd

ALPHA = 26

def modinv(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def decrypt_affine(ct, a, b):
    inv = modinv(a, ALPHA)
    if inv is None:
        raise ValueError("a has no inverse mod 26")
    res = []
    for ch in ct:
        if ch.isalpha():
            y = ord(ch.upper()) - 65
            x = (inv * (y - b)) % ALPHA
            res.append(chr(x + 65))
        else:
            res.append(ch)
    return ''.join(res)

# brute-force all possible (a,b) with gcd(a,26)=1 and check the known mapping "ab" -> "GL"
found = []
for a in range(1, ALPHA):
    if gcd(a, ALPHA) != 1:
        continue
    for b in range(ALPHA):
        # compute encryption of 'a' (0) and 'b' (1) under (a,b)
        enc_a = (a * 0 + b) % ALPHA      # should equal ord('G')-65 == 6
        enc_b = (a * 1 + b) % ALPHA      # should equal ord('L')-65 == 11
        if enc_a == (ord('G') - 65) and enc_b == (ord('L') - 65):
            pt = decrypt_affine(cipher, a, b)
            found.append((a, b, pt))

# print results
for a, b, pt in found:
    print(f"Discovered key: a={a}, b={b}")
    print("Decrypted plaintext:", pt)
