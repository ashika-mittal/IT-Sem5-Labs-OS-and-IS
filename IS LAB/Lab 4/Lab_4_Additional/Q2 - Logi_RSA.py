from math import gcd, isqrt

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(e, phi):
    g, x, y = egcd(e, phi)
    if g != 1:
        return None  # No modular inverse if gcd != 1
    else:
        return x % phi

def factor_modulus(n):
    # Naive trial division to find a factor (demonstration only)
    limit = isqrt(n) + 1
    for i in range(2, limit):
        if n % i == 0:
            return i, n // i
    return None, None

# Vulnerable RSA parameters (example small/insecure primes for demonstration)
n = 220459  # Example modulus (product of p and q)
e = 65537   # Public exponent

# Eve obtains partial key and tries to factor n
p, q = factor_modulus(n)
if p is None or q is None:
    print("Failed to factor modulus.")
else:
    print(f"Factors found: p = {p}, q = {q}")
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    if d is None:
        print("No modular inverse found; invalid parameters.")
    else:
        print(f"Recovered private exponent d: {d}")

        # Example ciphertext (encrypted integer)
        ciphertext = 58703

        # Decrypting ciphertext
        plaintext = pow(ciphertext, d, n)
        print(f"Decrypted plaintext integer: {plaintext}")

        # If plaintext encodes text, convert to string
        plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7)//8, 'big')
        try:
            print(f"Decrypted plaintext string: {plaintext_bytes.decode()}")
        except:
            print("Plaintext cannot be decoded to a string - may be numeric data.")
