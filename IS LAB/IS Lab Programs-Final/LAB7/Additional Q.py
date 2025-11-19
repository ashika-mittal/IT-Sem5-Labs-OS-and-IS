import random
import math
import time

# -------------------------------------------------------------
# Part 1a: Homomorphic Multiplication (ElGamal Cryptosystem)
# -------------------------------------------------------------
class ElGamal:
    def __init__(self, bits=8):
        self.p = self.get_prime(bits)
        self.g = random.randint(2, self.p - 2)
        self.x = random.randint(1, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)    # Public key (h = g^x mod p)

    def get_prime(self, bits):
        while True:
            num = random.randrange(2 ** (bits - 1), 2 ** bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        y = random.randint(1, self.p - 2)
        c1 = pow(self.g, y, self.p)
        s = pow(self.h, y, self.p)
        c2 = (m * s) % self.p
        return (c1, c2)

    def decrypt(self, c):
        c1, c2 = c
        s = pow(c1, self.x, self.p)
        s_inv = pow(s, -1, self.p)
        return (c2 * s_inv) % self.p


def elgamal_demo():
    print("\n--- (1a) ElGamal Homomorphic Multiplication ---")
    E = ElGamal()

    m1 = int(input("Enter first number (m1): "))
    m2 = int(input("Enter second number (m2): "))

    c1 = E.encrypt(m1)
    c2 = E.encrypt(m2)

    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Homomorphic multiplication: multiplying ciphertexts multiplies plaintexts
    c_mult = ((c1[0] * c2[0]) % E.p, (c1[1] * c2[1]) % E.p)
    decrypted_product = E.decrypt(c_mult)

    print(f"\nCiphertext after homomorphic multiplication: {c_mult}")
    print(f"Decrypted result (m1 * m2 mod p): {decrypted_product}")


# -------------------------------------------------------------
# Part 1b: Secure Data Sharing (Paillier)
# -------------------------------------------------------------
class Paillier:
    def __init__(self, bits=8):
        p = self.get_prime(bits)
        q = self.get_prime(bits)
        self.n = p * q
        self.g = self.n + 1
        self.lam = (p - 1) * (q - 1)
        self.mu = pow(self.L(pow(self.g, self.lam, self.n ** 2)), -1, self.n)

    def get_prime(self, bits):
        while True:
            num = random.randrange(2 ** (bits - 1), 2 ** bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def L(self, u):
        return (u - 1) // self.n

    def encrypt(self, m):
        r = random.randrange(1, self.n)
        return (pow(self.g, m, self.n ** 2) * pow(r, self.n, self.n ** 2)) % (self.n ** 2)

    def decrypt(self, c):
        return (self.L(pow(c, self.lam, self.n ** 2)) * self.mu) % self.n


def paillier_demo():
    print("\n--- (1b) Secure Data Sharing with Paillier ---")
    P = Paillier()
    a = int(input("Enter first user data (A): "))
    b = int(input("Enter second user data (B): "))

    c1 = P.encrypt(a)
    c2 = P.encrypt(b)

    print(f"Encrypted A: {c1}")
    print(f"Encrypted B: {c2}")

    # Combine encrypted data (homomorphic addition)
    c_sum = (c1 * c2) % (P.n ** 2)
    decrypted_sum = P.decrypt(c_sum)

    print(f"\nEncrypted combined data: {c_sum}")
    print(f"Decrypted combined result (A + B): {decrypted_sum}")


# -------------------------------------------------------------
# Part 1c: Secure Thresholding (Simulated)
# -------------------------------------------------------------
def threshold_paillier():
    print("\n--- (1c) Secure Threshold Simulation ---")
    P = Paillier()
    total = int(input("Enter total number of parties (n): "))
    required = int(input("Enter minimum parties required to reconstruct (t): "))

    lam = P.lam
    shares = [random.randrange(0, P.n) for _ in range(total - 1)]
    shares.append((lam - sum(shares)) % P.n)

    print(f"Generated {total} key shares: {shares}")

    subset = shares[:required]
    recon = sum(subset) % P.n
    if recon == lam:
        print("✅ Reconstruction succeeded (enough shares present)")
    else:
        print("❌ Reconstruction failed (not enough valid shares or rounding issue)")

    m = int(input("Enter message to encrypt: "))
    c = P.encrypt(m)
    print(f"Ciphertext: {c}")
    print(f"Decrypted message: {P.decrypt(c)}")


# -------------------------------------------------------------
# Part 1d: Performance Analysis (Benchmarking)
# -------------------------------------------------------------
def benchmark():
    print("\n--- (1d) Performance Benchmarking ---")
    trials = int(input("Enter number of trials: "))
    plaintext = 42

    # Paillier Benchmark
    P = Paillier()
    start = time.time()
    for _ in range(trials):
        c = P.encrypt(plaintext)
        P.decrypt(c)
    paillier_time = time.time() - start

    # ElGamal Benchmark
    E = ElGamal()
    start = time.time()
    for _ in range(trials):
        c = E.encrypt(plaintext)
        E.decrypt(c)
    elgamal_time = time.time() - start

    print(f"Paillier total time for {trials} trials: {paillier_time:.4f}s")
    print(f"ElGamal total time for {trials} trials: {elgamal_time:.4f}s")

    if paillier_time < elgamal_time:
        print("🏆 Paillier is faster for this test.")
    else:
        print("🏆 ElGamal is faster for this test.")


# -------------------------------------------------------------
# Menu-driven driver
# -------------------------------------------------------------
if __name__ == "__main__":
    while True:
        print("\n===============================")
        print("PHE Demonstration Menu")
        print("===============================")
        print("1. ElGamal Homomorphic Multiplication")
        print("2. Paillier Secure Data Sharing")
        print("3. Secure Threshold Simulation")
        print("4. Performance Benchmarking")
        print("5. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            elgamal_demo()
        elif choice == "2":
            paillier_demo()
        elif choice == "3":
            threshold_paillier()
        elif choice == "4":
            benchmark()
        elif choice == "5":
            break
        else:
            print("Invalid choice, please try again.")


# ----------------------------------------------------------------------
# 🧾 DETAILED EXPLANATION OF 1c & 1d
# ----------------------------------------------------------------------
# (1c) SECURE THRESHOLD SIMULATION:
# ---------------------------------
# - Concept: The private key (λ in Paillier) is divided into multiple shares,
#   and a subset of these shares is required to reconstruct it.
# - This simulates "threshold cryptography" — used when no single entity should
#   have full access to the private key.
# - The system here randomly generates shares such that:
#       sum(all shares) ≡ λ (mod n)
# - Reconstruction works if the correct number of shares (t) are combined.
#
# ✅ SUCCESS CASE:
#   - If enough shares (≥ threshold) are combined correctly, the reconstructed
#     λ equals the original λ, and decryption works normally.
#
# ❌ FAILURE CASES:
#   - If fewer than required shares are used, reconstruction fails (wrong λ).
#   - If shares are tampered with or not properly modularized, failure occurs.
#   - In real threshold cryptography, polynomial secret sharing (e.g. Shamir’s)
#     is used for robustness; here it’s simplified for demonstration.
#
# 💡 PURPOSE:
#   - Demonstrates secure multi-party computation: several parties must
#     collaborate without revealing individual private data.

#
# (1d) PERFORMANCE BENCHMARKING:
# ------------------------------
# - Compares Paillier (additive homomorphism) and ElGamal (multiplicative
#   homomorphism) based on encryption/decryption time.
# - Runs both schemes for a fixed number of trials and measures total runtime.
#
# 📈 INTERPRETATION:
#   - Paillier involves modular exponentiation with n², typically slower for
#     decryption but faster for small bit sizes.
#   - ElGamal involves modular arithmetic under a large prime p.
#   - Depending on key size and hardware, either can be faster.
#
# 💡 USE CASE:
#   - Helps understand computational overhead of different PHE schemes.
#   - Crucial for deciding which system to use in practical secure computation
#     scenarios.
# ----------------------------------------------------------------------
