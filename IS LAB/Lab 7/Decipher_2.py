from Crypto.Util.number import getPrime, inverse
from math import gcd

# ---------- RSA Key Generation ----------
def generate_keys(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
    d = inverse(e, phi)
    return (e, n), (d, n)

# ---------- Encryption ----------
def encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)

# ---------- Decryption ----------
def decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)

# ---------- Demonstration ----------
if __name__ == "__main__":
    pub, priv = generate_keys()
    e, n = pub

    # Plaintexts
    m1, m2 = 7, 3
    print("Plaintexts:", m1, m2)

    # Encrypt both
    c1 = encrypt(m1, pub)
    c2 = encrypt(m2, pub)
    print("\nCiphertext 1:", c1)
    print("Ciphertext 2:", c2)

    # Homomorphic multiplication
    c_mul = (c1 * c2) % n
    print("\nEncrypted Multiplication (c1 * c2 mod n):", c_mul)

    # Decrypt the multiplication result
    decrypted_product = decrypt(c_mul, priv)
    print("\nDecrypted Product:", decrypted_product)
    print("Expected Product:", m1 * m2)

    if decrypted_product == (m1 * m2):
        print("\nHomomorphic multiplication verified successfully!")
    else:
        print("\nVerification failed.")
