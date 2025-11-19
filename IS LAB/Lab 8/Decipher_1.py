from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import re

# =========================================================
# 1a. CREATE DATASET (10 DOCUMENTS)
# =========================================================
documents = {
    1: "Information security is crucial in the modern world",
    2: "Cryptography ensures confidentiality and integrity",
    3: "Symmetric encryption uses the same key for both encryption and decryption",
    4: "Asymmetric encryption uses public and private keys",
    5: "Hashing ensures integrity but not confidentiality",
    6: "The AES algorithm is widely used for data security",
    7: "Searchable symmetric encryption enables secure search",
    8: "Homomorphic encryption allows computation on ciphertexts",
    9: "ElGamal and RSA are public key algorithms",
    10: "Secure search and indexing are important for encrypted databases"
}

# =========================================================
# 1b. AES ENCRYPTION & DECRYPTION FUNCTIONS
# =========================================================
def pad(text):
    return text + ' ' * (16 - len(text) % 16)

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plaintext).encode('utf-8'))
    return base64.b64encode(ct_bytes).decode('utf-8')

def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8').strip()
    return pt

# Generate AES key (shared symmetric key)
aes_key = get_random_bytes(16)

# =========================================================
# 1c. BUILD INVERTED INDEX
# =========================================================
def build_inverted_index(docs):
    index = {}
    for doc_id, text in docs.items():
        words = re.findall(r'\b\w+\b', text.lower())
        for word in words:
            index.setdefault(word, set()).add(doc_id)
    return index

inverted_index = build_inverted_index(documents)

print("\nPlain Inverted Index:")
for k, v in inverted_index.items():
    print(k, ":", v)

# Encrypt each word (key) and document IDs (values)
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    enc_word = aes_encrypt(aes_key, word)
    enc_docs = [aes_encrypt(aes_key, str(doc_id)) for doc_id in doc_ids]
    encrypted_index[enc_word] = enc_docs

print("\nEncrypted Inverted Index created successfully!")

# =========================================================
# 1d. SEARCH FUNCTION
# =========================================================
def search_query(query, encrypted_index, key):
    enc_query = aes_encrypt(key, query.lower())
    if enc_query in encrypted_index:
        enc_doc_ids = encrypted_index[enc_query]
        doc_ids = [int(aes_decrypt(key, enc_id)) for enc_id in enc_doc_ids]
        return doc_ids
    else:
        return []

# =========================================================
# USER INTERACTION
# =========================================================
while True:
    query = input("\nEnter a word to search (or 'exit' to quit): ").strip().lower()
    if query == "exit":
        print("Exiting...")
        break
    results = search_query(query, encrypted_index, aes_key)
    if results:
        print(f"\nWord '{query}' found in documents: {results}")
        for doc_id in results:
            print(f"Doc {doc_id}: {documents[doc_id]}")
    else:
        print(f"\nWord '{query}' not found in any document.")
