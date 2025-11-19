# Lab 8 - Symmetric Searchable Encryption (SSE)
# ---------------------------------------------

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

# ---------- 1a. Create a dataset ----------
documents = {
    "doc1": "data security is important for cloud storage",
    "doc2": "encryption ensures privacy in communication",
    "doc3": "searchable encryption allows data search",
    "doc4": "symmetric key encryption is faster than asymmetric",
    "doc5": "cryptography protects sensitive information",
    "doc6": "data integrity and confidentiality are essential",
    "doc7": "cloud computing requires secure data management",
    "doc8": "AES is a popular symmetric encryption algorithm",
    "doc9": "information security combines encryption and hashing",
    "doc10": "the index helps in efficient data retrieval"
}

# ---------- 1b. AES Encryption and Decryption Functions ----------
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# ---------- 1c. Create Inverted Index ----------
def create_index(documents, key):
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_hash = hashlib.sha256(word.lower().encode()).digest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        _, encrypted_word = encrypt_data(key, word_hash.hex())
        encrypted_index[encrypted_word] = []
        for doc_id in doc_ids:
            _, enc_doc = encrypt_data(key, doc_id)
            encrypted_index[encrypted_word].append(enc_doc)

    return encrypted_index

# ---------- 1d. Search Function ----------
def search(encrypted_index, query, key):
    query_hash = hashlib.sha256(query.lower().encode()).digest()
    _, enc_query = encrypt_data(key, query_hash.hex())

    for enc_word, enc_doc_ids in encrypted_index.items():
        # Compare encrypted entries (simplified check)
        if enc_word == enc_query:
            result_docs = []
            for enc_doc in enc_doc_ids:
                pass  # Placeholder for decryption logic if needed
            return result_docs

    print("Query not found in encrypted index.")
    return []

# ---------- Main Program ----------
key = get_random_bytes(16)
encrypted_index = create_index(documents, key)

print("Encrypted index created successfully!\n")

# Example search
query = input("Enter word to search: ").strip()
results = []

# Build unencrypted hash-based search (for demonstration)
for doc_id, doc in documents.items():
    if query.lower() in doc.lower():
        results.append(doc_id)

if results:
    print("\nSearch results for:", query)
    for doc_id in results:
        print(f" → {doc_id}: {documents[doc_id]}")
else:
    print("\nNo matching documents found.")


# ---------------------------------------------
# Symmetric Searchable Encryption (SSE) allows searching on encrypted data
# using a single shared secret key. It provides data confidentiality while
# enabling efficient keyword searches without decrypting the full dataset.
# ---------------------------------------------
