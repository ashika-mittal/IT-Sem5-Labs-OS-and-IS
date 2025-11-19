from Crypto.Util.number import getPrime, inverse
import re
import random
import math

# =========================================================
# 2b. PAILLIER ENCRYPTION & DECRYPTION FUNCTIONS
# =========================================================
def lcm(a, b):
    return a * b // math.gcd(a, b)

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

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n * n
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n * n
    def L(u): return (u - 1) // n
    u = pow(c, lam, nsq)
    l_val = L(u)
    m = (l_val * mu) % n
    return m

# =========================================================
# 2a. CREATE DATASET (10 DOCUMENTS)
# =========================================================
documents = {
    1: "Cloud computing and data security are important topics",
    2: "Homomorphic encryption enables computation on ciphertexts",
    3: "The Paillier cryptosystem is additive homomorphic",
    4: "Public key encryption is slower but more secure",
    5: "Symmetric encryption uses a shared secret key",
    6: "Searchable encryption allows secure search over encrypted data",
    7: "Data privacy is essential in modern applications",
    8: "Cryptography provides confidentiality and authentication",
    9: "Information security is a multidisciplinary field",
    10: "Secure data sharing is enabled by cryptographic techniques"
}

# =========================================================
# 2c. BUILD ENCRYPTED INVERTED INDEX
# =========================================================
def build_inverted_index(docs):
    index = {}
    for doc_id, text in docs.items():
        words = re.findall(r'\b\w+\b', text.lower())
        for word in words:
            index.setdefault(word, set()).add(doc_id)
    return index

# Generate Paillier keypair
pub, priv = paillier_keygen()

# Build inverted index (plain)
inverted_index = build_inverted_index(documents)
print("\nPlain Inverted Index:")
for k, v in inverted_index.items():
    print(k, ":", v)

# Encrypt the index using Paillier (encrypt each document ID)
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    enc_ids = [paillier_encrypt(pub, doc_id) for doc_id in doc_ids]
    encrypted_index[word] = enc_ids

print("\nEncrypted Index created successfully!")

# =========================================================
# 2d. SEARCH FUNCTION
# =========================================================
def search_query(query, encrypted_index, pub, priv):
    query = query.lower()
    print(f"\nEncrypted search for: '{query}'")

    if query not in encrypted_index:
        print("No matching word found in encrypted index.")
        return []

    enc_doc_ids = encrypted_index[query]
    doc_ids = [paillier_decrypt(pub, priv, enc_id) for enc_id in enc_doc_ids]
    return doc_ids

# =========================================================
# USER INTERACTION
# =========================================================
while True:
    query = input("\nEnter word to search (or 'exit' to quit): ").strip().lower()
    if query == "exit":
        print("Exiting PKSE demo...")
        break
    results = search_query(query, encrypted_index, pub, priv)
    if results:
        print(f"Word '{query}' found in documents: {results}")
        for doc_id in results:
            print(f"Doc {doc_id}: {documents[doc_id]}")
    else:
        print(f"Word '{query}' not found in any document.")
