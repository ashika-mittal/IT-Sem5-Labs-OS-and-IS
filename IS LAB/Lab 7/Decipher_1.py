from math import gcd
from Crypto.Util.number import getPrime
import random

# ---------- Key Generation ----------
def lcm(a, b):
    return a * b // gcd(a, b)

def paillier_keygen(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    nsq = n * n
    g = n + 1
    lam = lcm(p - 1, q - 1)
    def L(u): return (u - 1) // n
    x = pow(g, lam, nsq)
    l_val = L(x)
    mu = pow(l_val, -1, n)
    return (n, g), (lam, mu)

# ---------- Encryption ----------
def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n * n
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

# ---------- Decryption ----------
def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n * n
    def L(u): return (u - 1) // n
    u = pow(c, lam, nsq)
    l_val = L(u)
    m = (l_val * mu) % n
    return m

# ---------- Demonstration ----------
if __name__ == "__main__":
    pub, priv = paillier_keygen()
    print("Public key (n, g):", pub)
    print("Private key (λ, μ):", priv)

    # Two integers
    #m1, m2 = 15, 25
    #print("\nPlaintexts:", m1, m2)

    a1=int(input("Enter the first integer: "))
    a2=int(input("Enter the second integer: "))

    # Encrypt both
    c1 = paillier_encrypt(pub, a1)
    c2 = paillier_encrypt(pub, a2)
    print("\nCiphertext 1:", c1)
    print("Ciphertext 2:", c2)

    # Homomorphic addition (encrypted)
    c_sum = (c1 * c2) % (pub[0] ** 2)
    print("\nEncrypted Sum (c1 * c2 mod n²):", c_sum)

    # Decrypt the result
    decrypted_sum = paillier_decrypt(pub, priv, c_sum)
    print("\nDecrypted Sum:", decrypted_sum)
    print("Expected Sum:", a1 + a2)

    if decrypted_sum == (a1 + a2):
        print("\nHomomorphic addition verified successfully!")
    else:
        print("\nVerification failed.")
