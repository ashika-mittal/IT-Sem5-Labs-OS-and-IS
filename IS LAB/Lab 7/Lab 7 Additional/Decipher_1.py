#!/usr/bin/env python3
"""
phe_examples.py

Demonstrates:
1a) ElGamal multiplicative homomorphism (encrypt, multiply ciphertexts, decrypt product)
1b) Paillier secure data sharing: two parties encrypt values with server's Paillier pubkey; server homomorphically adds and decrypts
1c) Threshold-style demo: split Paillier private lambda using Shamir secret sharing; reconstruct with k shares to decrypt
1d) Benchmarking: compare timings for ElGamal vs Paillier for common ops

Requirements:
 - Python 3.8+
 - pycryptodome: pip install pycryptodome
"""

import random, time, math
from Crypto.Util.number import getPrime, inverse
import hashlib
from functools import reduce
from operator import mul

# ---------------------------
# Utilities
# ---------------------------
def lcm(a,b): return a//math.gcd(a,b)*b

# ---------------------------
# ElGamal (multiplicative PHE)
# ---------------------------
def elgamal_keygen(bits=512):
    p = getPrime(bits)
    g = 2
    # ensure g is valid generator-ish (for demo we use 2)
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    pub = (p, g, y)
    priv = (p, g, x)
    return pub, priv

def elgamal_encrypt(pub, m):
    p,g,y = pub
    k = random.randrange(2, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(priv, ct):
    p,g,x = priv
    c1, c2 = ct
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    return m

def elgamal_homomorphic_mul(ct1, ct2, p):
    # Multiply corresponding components
    c1 = (ct1[0] * ct2[0]) % p
    c2 = (ct1[1] * ct2[1]) % p
    return (c1, c2)

# ---------------------------
# Paillier (additive PHE)
# ---------------------------
def paillier_keygen(bits=512):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    nsq = n * n
    g = n + 1
    lam = lcm(p-1, q-1)
    # L(u) = (u-1)//n
    def L(u): return (u - 1) // n
    x = pow(g, lam, nsq)
    lval = L(x)
    mu = inverse(lval, n)
    pub = (n, g)
    priv = (lam, mu, p, q)
    return pub, priv

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n * n
    if not (0 <= m < n):
        raise ValueError("m out of range")
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu, p, q = priv
    nsq = n * n
    def L(u): return (u - 1) // n
    u = pow(c, lam, nsq)
    lval = L(u)
    m = (lval * mu) % n
    return m

def paillier_homomorphic_add(pub, c1, c2):
    n, g = pub
    nsq = n * n
    return (c1 * c2) % nsq

# ---------------------------
# Shamir Secret Sharing (simple)
# ---------------------------
# We will use a prime field > secret. This is a demo to split and reconstruct integer secrets.
def random_polynomial(secret, degree, prime):
    # returns coefficients [a0=secret, a1, ..., adegree]
    coeffs = [secret] + [random.randrange(0, prime) for _ in range(degree)]
    return coeffs

def eval_poly(coeffs, x, prime):
    res = 0
    for i, a in enumerate(coeffs):
        res = (res + a * pow(x, i, prime)) % prime
    return res

def make_shares(secret, n_shares, threshold, prime):
    coeffs = random_polynomial(secret, threshold-1, prime)
    shares = []
    for i in range(1, n_shares+1):
        shares.append((i, eval_poly(coeffs, i, prime)))
    return shares

def lagrange_interpolate(x, x_s, y_s, p):
    # interpolate f(0) using x_s and y_s (Lagrange basis), return f(x)
    assert len(x_s) == len(y_s)
    k = len(x_s)
    total = 0
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num = 1
        den = 1
        for j in range(k):
            if j == i: continue
            xj = x_s[j]
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        inv_den = inverse(den, p)
        total = (total + yi * num * inv_den) % p
    return total

# ---------------------------
# Benchmarking helpers
# ---------------------------
def time_it(fn, *args, repeat=20):
    start = time.perf_counter()
    for _ in range(repeat):
        fn(*args)
    end = time.perf_counter()
    return (end - start) / repeat

# ---------------------------
# Demos
# ---------------------------
def demo_1a_elgamal_mul():
    print("\n--- 1a) ElGamal multiplicative homomorphism demo ---")
    pub, priv = elgamal_keygen(bits=512)
    p, g, y = pub
    m1, m2 = 7, 3
    print("Plaintexts:", m1, m2)

    c1 = elgamal_encrypt(pub, m1)
    c2 = elgamal_encrypt(pub, m2)
    print("Ciphertext1:", c1)
    print("Ciphertext2:", c2)

    # Homomorphic multiplication
    c_mul = elgamal_homomorphic_mul(c1, c2, p)
    print("Encrypted product (mul of ciphertexts):", c_mul)

    dec = elgamal_decrypt(priv, c_mul)
    print("Decrypted product:", dec, "Expected:", m1 * m2)
    print("Success:", dec == m1 * m2)

def demo_1b_paillier_sharing():
    print("\n--- 1b) Paillier secure data sharing demo ---")
    pub, priv = paillier_keygen(bits=512)
    n, g = pub
    print("Paillier public n (bits):", n.bit_length())

    # Two parties encrypt values with server's pubkey
    a, b = 15, 25
    ca = paillier_encrypt(pub, a)
    cb = paillier_encrypt(pub, b)
    print("Cipher a:", ca)
    print("Cipher b:", cb)

    # Server homomorphically adds (multiplication mod n^2)
    csum = paillier_homomorphic_add(pub, ca, cb)
    print("Encrypted sum (cipher product):", csum)

    # Server decrypts sum
    dec_sum = paillier_decrypt(pub, priv, csum)
    print("Decrypted sum:", dec_sum, "Expected:", a + b)
    print("Success:", dec_sum == a + b)

def demo_1c_threshold_paillier():
    print("\n--- 1c) Threshold-style Paillier demo (educational) ---")
    print("CAVEAT: This is a *demonstration* using Shamir share of the private λ value.")
    print("Real threshold Paillier uses distributed key generation and special protocols.\n")

    # Generate Paillier keys
    pub, priv = paillier_keygen(bits=512)
    n, g = pub
    lam, mu, p, q = priv
    print("Private lambda (λ) bit-length:", lam.bit_length())

    # Create shares of lambda using Shamir (n_shares, threshold k)
    n_shares = 5
    k = 3
    # choose a prime > lambda for field (use next prime roughly)
    prime_field = get_prime_above(lam + 1000)  # helper below
    shares = make_shares(lam, n_shares, k, prime_field)
    print(f"Created {n_shares} shares, threshold {k}. Example shares:", shares[:3])

    # Simulate parties encrypting values
    vals = [10, 20, 5]  # three parties
    ciphers = [paillier_encrypt(pub, v) for v in vals]
    agg = 1
    for c in ciphers: agg = paillier_homomorphic_add(pub, agg, c)
    print("Aggregated ciphertext ready.")

    # Suppose some k parties provide their shares -> reconstruct lambda
    sample_shares = shares[:k]
    x_s = [s[0] for s in sample_shares]
    y_s = [s[1] for s in sample_shares]
    recon_lam = lagrange_interpolate(0, x_s, y_s, prime_field)
    recon_lam = recon_lam % prime_field
    print("Reconstructed lambda (mod prime_field). Equal to original mod prime_field?:", recon_lam == lam % prime_field)

    # For demonstration, attempt decryption using reconstructed lambda and original mu.
    # NOTE: this is only to illustrate reconstruct->decrypt; proper threshold needs mu split / special protocol.
    def L(u): return (u - 1) // n
    nsq = n * n
    u = pow(agg, recon_lam, nsq)
    lval = L(u)
    # mu is still the original; in real threshold mu must be computed distributedly
    dec = (lval * mu) % n
    print("Decrypted aggregate (with reconstructed lambda & original mu):", dec, "Expected:", sum(vals))
    print("Note: This works here only because mu is known to the reconstructing party; real threshold Paillier avoids sharing mu.")

def get_prime_above(x):
    # find a slightly larger prime for the Shamir field (not optimized)
    candidate = x | 1
    while True:
        if is_prime(candidate):
            return candidate
        candidate += 2

def is_prime(n):
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n-1; s = 0
    while d % 2 == 0:
        d//=2; s+=1
    def try_composite(a):
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            return False
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                return False
        return True
    for a in [2,325,9375,28178,450775,9780504,1795265022]:
        if a % n == 0:
            return True
        if try_composite(a):
            return False
    return True

def demo_1d_benchmark():
    print("\n--- 1d) Performance benchmarking (ElGamal vs Paillier) ---")
    # sizes and repeats
    bits_el = 512
    bits_pail = 512
    repeats = 20

    # ElGamal timings
    t0 = time.perf_counter()
    pub_e, priv_e = elgamal_keygen(bits=bits_el)
    t_key_e = time.perf_counter() - t0

    # Paillier timings
    t0 = time.perf_counter()
    pub_p, priv_p = paillier_keygen(bits=bits_pail)
    t_key_p = time.perf_counter() - t0

    # encryption average
    enc_el_time = time_it(lambda: elgamal_encrypt(pub_e, 123), repeat=repeats)
    enc_p_time = time_it(lambda: paillier_encrypt(pub_p, 123), repeat=repeats)

    # homomorphic op average: multiply ciphers
    c1 = elgamal_encrypt(pub_e, 7); c2 = elgamal_encrypt(pub_e, 3)
    hom_el_time = time_it(lambda: elgamal_homomorphic_mul(c1, c2, pub_e[0]), repeat=repeats)

    cpa = paillier_encrypt(pub_p, 15); cpb = paillier_encrypt(pub_p, 25)
    hom_p_time = time_it(lambda: paillier_homomorphic_add(pub_p, cpa, cpb), repeat=repeats)

    # decryption average
    dec_el_time = time_it(lambda: elgamal_decrypt(priv_e, c1), repeat=repeats)
    dec_p_time = time_it(lambda: paillier_decrypt(pub_p, priv_p, cpa), repeat=repeats)

    print("Keygen time (ElGamal): {:.4f}s, (Paillier): {:.4f}s".format(t_key_e, t_key_p))
    print("Avg encrypt time (ElGamal): {:.6f}s, (Paillier): {:.6f}s".format(enc_el_time, enc_p_time))
    print("Avg hom op time (ElGamal): {:.6f}s, (Paillier): {:.6f}s".format(hom_el_time, hom_p_time))
    print("Avg decrypt time (ElGamal): {:.6f}s, (Paillier): {:.6f}s".format(dec_el_time, dec_p_time))
    print("\nNote: timings depend on implementation, bit sizes, and hardware. This is a simple lab benchmark.")

def time_it(fn, repeat=50):
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - start) / repeat

# ---------------------------
# Run all demos in sequence
# ---------------------------
if __name__ == "__main__":
    demo_1a_elgamal_mul()
    demo_1b_paillier_sharing()
    demo_1c_threshold_paillier()
    demo_1d_benchmark()
