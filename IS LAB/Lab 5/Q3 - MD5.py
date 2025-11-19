import hashlib
import random
import string
import time

# Generate random strings
def gen_strings(n=50, length=20):
    return [''.join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(n)]

# Hash functions
def md5_hash(s): return hashlib.md5(s.encode()).hexdigest()
def sha1_hash(s): return hashlib.sha1(s.encode()).hexdigest()
def sha256_hash(s): return hashlib.sha256(s.encode()).hexdigest()

# Detect collisions
def has_collision(hashes):
    return len(set(hashes)) != len(hashes)

# Main
data = gen_strings(random.randint(50, 100))

start = time.time()
md5_hashes = [md5_hash(s) for s in data]
print("MD5 Time:", time.time() - start, "seconds, Collisions:", has_collision(md5_hashes))

start = time.time()
sha1_hashes = [sha1_hash(s) for s in data]
print("SHA-1 Time:", time.time() - start, "seconds, Collisions:", has_collision(sha1_hashes))

start = time.time()
sha256_hashes = [sha256_hash(s) for s in data]
print("SHA-256 Time:", time.time() - start, "seconds, Collisions:", has_collision(sha256_hashes))
