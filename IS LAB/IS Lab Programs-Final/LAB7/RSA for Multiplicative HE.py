import random
import math

# ------------------------------------------------------------
# Step 1: Compute GCD using Euclidean algorithm
# ------------------------------------------------------------
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# ------------------------------------------------------------
# Step 2: Compute modular inverse (for private key)
# ------------------------------------------------------------
def mod_inverse(e, phi):
    # Using Extended Euclidean Algorithm
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, y = egcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

# ------------------------------------------------------------
# Step 3: Generate RSA public and private keys
# ------------------------------------------------------------
def generate_keys():
    # NOTE: p and q must be prime numbers
    p = 17
    q = 19
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent e such that gcd(e, phi) = 1
    e = 7
    while gcd(e, phi) != 1:
        e += 2  # choose next odd number

    # Compute private key exponent d = e⁻¹ mod φ(n)
    d = mod_inverse(e, phi)

    # Public key = (e, n), Private key = (d, n)
    return (e, n), (d, n)

# ------------------------------------------------------------
# Step 4: RSA Encryption
# ------------------------------------------------------------
def encrypt(pub_key, plaintext):
    e, n = pub_key
    # Encryption formula: c = m^e mod n
    return pow(plaintext, e, n)

# ------------------------------------------------------------
# Step 5: RSA Decryption
# ------------------------------------------------------------
def decrypt(priv_key, ciphertext):
    d, n = priv_key
    # Decryption formula: m = c^d mod n
    return pow(ciphertext, d, n)

# ------------------------------------------------------------
# Step 6: Homomorphic Multiplication
# ------------------------------------------------------------
def homomorphic_multiply(c1, c2, n):
    # Multiplication of ciphertexts = multiplication of plaintexts
    # c3 = (c1 * c2) mod n
    return (c1 * c2) % n

# ------------------------------------------------------------
# Step 7: Main Program
# ------------------------------------------------------------
if __name__ == "__main__":
    print("---- RSA Homomorphic Encryption ----")

    # Generate RSA key pair
    public_key, private_key = generate_keys()
    e, n = public_key
    d, _ = private_key

    # User input
    m1 = int(input("Enter first integer: "))
    m2 = int(input("Enter second integer: "))

    # Encrypt both integers
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)

    # Display ciphertexts
    print(f"\nCiphertext of {m1} :", c1)
    print(f"Ciphertext of {m2} :", c2)

    # Perform homomorphic multiplication on encrypted values
    c_product = homomorphic_multiply(c1, c2, n)
    print(f"\nCiphertext of ({m1} * {m2}):", c_product)

    # Decrypt the result to verify
    decrypted_product = decrypt(private_key, c_product)
    print(f"Decrypted Product = {decrypted_product}")

# ------------------------------------------------------------
# 📘 Explanation:
# ------------------------------------------------------------
# RSA Cryptosystem is a PARTIALLY HOMOMORPHIC ENCRYPTION (PHE) scheme
# that supports MULTIPLICATION on encrypted data.
#
# The key mathematical property is:
#     E(m1) * E(m2) mod n = E(m1 * m2)
#
# This means multiplying ciphertexts gives a ciphertext
# that decrypts to the product of the original plaintexts.
#
# p and q must be prime numbers to ensure that φ(n) = (p−1)(q−1)
# has the right properties for modular arithmetic.
# ------------------------------------------------------------
