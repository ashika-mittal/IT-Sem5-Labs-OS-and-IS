import hashlib
import random
import string
import time


# ---------------- Helper Function ----------------
def random_string(length=10):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def generate_dataset(size=None):
    dataset_size = size if size else random.randint(50, 100)
    return [random_string(random.randint(8, 16)) for _ in range(dataset_size)]


# ---------------- MD5 Hashing ----------------
def hash_md5(dataset):
    hashes = {}
    collisions = []
    start_time = time.time()

    print("\n=== MD5 Hashing ===")
    for s in dataset:
        h = hashlib.md5(s.encode()).hexdigest()   # <-- HASH GENERATED
        print(f"{s} -> {h}")                      # <-- PRINT HASH
        if h in hashes and hashes[h] != s:
            collisions.append((hashes[h], s))
        else:
            hashes[h] = s

    end_time = time.time()
    print(f"\nDataset size: {len(dataset)} random strings")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print(f"Collisions detected: {len(collisions)}")
    if collisions:
        print("Collision pairs:")
        for c in collisions:
            print(f"  {c[0]} <--> {c[1]}")


# ---------------- SHA-1 Hashing ----------------
def hash_sha1(dataset):
    hashes = {}
    collisions = []
    start_time = time.time()

    print("\n=== SHA-1 Hashing ===")
    for s in dataset:
        h = hashlib.sha1(s.encode()).hexdigest()  # <-- HASH GENERATED
        print(f"{s} -> {h}")                      # <-- PRINT HASH
        if h in hashes and hashes[h] != s:
            collisions.append((hashes[h], s))
        else:
            hashes[h] = s

    end_time = time.time()
    print(f"\nDataset size: {len(dataset)} random strings")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print(f"Collisions detected: {len(collisions)}")
    if collisions:
        print("Collision pairs:")
        for c in collisions:
            print(f"  {c[0]} <--> {c[1]}")


# ---------------- SHA-256 Hashing ----------------
def hash_sha256(dataset):
    hashes = {}
    collisions = []
    start_time = time.time()

    print("\n=== SHA-256 Hashing ===")
    for s in dataset:
        h = hashlib.sha256(s.encode()).hexdigest()  # <-- HASH GENERATED
        print(f"{s} -> {h}")                        # <-- PRINT HASH
        if h in hashes and hashes[h] != s:
            collisions.append((hashes[h], s))
        else:
            hashes[h] = s

    end_time = time.time()
    print(f"\nDataset size: {len(dataset)} random strings")
    print(f"Time taken: {end_time - start_time:.6f} seconds")
    print(f"Collisions detected: {len(collisions)}")
    if collisions:
        print("Collision pairs:")
        for c in collisions:
            print(f"  {c[0]} <--> {c[1]}")


# ---------------- Main ----------------
if __name__ == "__main__":
    dataset = generate_dataset()

    # Call whichever hashing function you want
    hash_md5(dataset)
    hash_sha1(dataset)
    hash_sha256(dataset)
