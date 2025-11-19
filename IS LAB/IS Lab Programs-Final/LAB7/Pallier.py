import random
import math

# ------------------------------------------------------------
# Function to calculate Least Common Multiple (used in key generation)
# ------------------------------------------------------------
def lcm(a, b):
    return a * b // math.gcd(a, b)

# ------------------------------------------------------------
# Step 1: Generate public and private keys
# ------------------------------------------------------------
def generate_keypair(p, q):
    # NOTE: p and q MUST be prime numbers.
    # This ensures that n = p*q has the correct mathematical properties
    # for encryption and decryption to work properly.
    n = p * q                        # n = p * q
    n_sq = n * n                     # n² used in encryption and decryption
    lam = lcm(p - 1, q - 1)          # λ = lcm(p-1, q-1)
    g = n + 1                        # common choice for g

    # μ = (L(g^λ mod n²))⁻¹ mod n
    x = pow(g, lam, n_sq)
    L = (x - 1) // n
    mu = pow(L, -1, n)

    public_key = (n, g)
    private_key = (lam, mu)
    return public_key, private_key

# ------------------------------------------------------------
# Step 2: Encrypt a plaintext integer
# ------------------------------------------------------------
def encrypt(pub_key, m):
    n, g = pub_key
    n_sq = n * n
    # Choose random r where 1 < r < n and gcd(r, n) = 1
    while True:
        r = random.randint(1, n - 1)
        if math.gcd(r, n) == 1:
            break
    # Encryption formula: E(m) = g^m * r^n mod n²
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# ------------------------------------------------------------
# Step 3: Decrypt the ciphertext back to plaintext
# ------------------------------------------------------------
def decrypt(priv_key, pub_key, c):
    lam, mu = priv_key
    n, g = pub_key
    n_sq = n * n
    # Decryption formula: m = (L(c^λ mod n²) * μ) mod n
    x = pow(c, lam, n_sq)
    L = (x - 1) // n
    m = (L * mu) % n
    return m

# ------------------------------------------------------------
# Step 4: Perform homomorphic addition
# ------------------------------------------------------------
def homomorphic_add(c1, c2, pub_key):
    n, g = pub_key
    n_sq = n * n
    # Addition of plaintexts = multiplication of ciphertexts
    return (c1 * c2) % n_sq

# ------------------------------------------------------------
# Step 5: Main Program
# ------------------------------------------------------------
if __name__ == "__main__":
    print("---- Paillier Homomorphic Encryption ----")

    # Use small prime numbers for demonstration (larger primes are used in real applications)
    p = 17
    q = 19

    # Generate public and private keys
    pub_key, priv_key = generate_keypair(p, q)

    # Take user input for two integers
    m1 = int(input("Enter first integer: "))
    m2 = int(input("Enter second integer: "))

    # Encrypt both integers
    c1 = encrypt(pub_key, m1)
    c2 = encrypt(pub_key, m2)

    # Display ciphertexts
    print("\nCiphertext of", m1, ":", c1)
    print("Ciphertext of", m2, ":", c2)

    # Perform homomorphic addition (without decrypting)
    c_sum = homomorphic_add(c1, c2, pub_key)
    print("\nCiphertext of (", m1, "+", m2, "):", c_sum)

    # Decrypt the result to verify correctness
    decrypted_sum = decrypt(priv_key, pub_key, c_sum)
    print("Decrypted Sum =", decrypted_sum)

# ------------------------------------------------------------
# 📘 Explanation:
# ------------------------------------------------------------
# Paillier Cryptosystem is a type of PARTIALLY HOMOMORPHIC ENCRYPTION (PHE)
# that supports ADDITION on encrypted data.
#
# It requires two large prime numbers p and q to generate keys.
# These primes ensure the mathematical properties needed for modular
# arithmetic and decryption to function correctly.
#
# Main property:
#     E(m1) * E(m2) mod n² = E(m1 + m2)
#
# So multiplying ciphertexts corresponds to adding plaintexts.
# This allows computations to be done securely on encrypted data.
# ------------------------------------------------------------
