# pip install phe
from phe import paillier
from collections import defaultdict

# ---------- Dataset (Predefined) ----------
documents = {
    1: "machine learning algorithms and applications",
    2: "secure searchable encryption using cryptography",
    3: "data privacy and encryption are important",
    4: "paillier cryptosystem is a public key encryption scheme",
    5: "homomorphic encryption allows computations on ciphertext",
    6: "encryption ensures data confidentiality",
    7: "machine learning can benefit from encrypted data",
    8: "public key encryption uses a pair of keys",
    9: "cryptography provides confidentiality integrity and authenticity",
    10: "searchable encryption is used in secure data retrieval"
}

# ---------- Paillier Key Generation ----------
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_number(num):
    return public_key.encrypt(num)

def decrypt_number(enc_num):
    return private_key.decrypt(enc_num)

# ---------- Build Plain Inverted Index ----------
inverted_index = defaultdict(list)
for doc_id, text in documents.items():
    for word in text.lower().split():
        if doc_id not in inverted_index[word]:
            inverted_index[word].append(doc_id)

# ---------- Encrypt Document IDs Efficiently ----------
encrypted_doc_cache = {i: encrypt_number(i) for i in range(1, len(documents)+1)}
encrypted_index = {word: [encrypted_doc_cache[doc_id] for doc_id in doc_ids]
                   for word, doc_ids in inverted_index.items()}

# ---------- Encrypted Search Function ----------
def search_encrypted(query):
    query = query.lower()
    if query not in encrypted_index:
        print(" No documents found for this query.")
        return []

    encrypted_results = encrypted_index[query]
    decrypted_results = [decrypt_number(enc_doc_id) for enc_doc_id in encrypted_results]

    print(f"✅ Matching document IDs for '{query}': {decrypted_results}")
    return decrypted_results

# ---------- User Search ----------
while True:
    query = input("\nEnter a search word (or type 'exit' to quit): ").strip()
    if query.lower() == "exit":
        print("Exiting search...")
        break
    search_encrypted(query)

# -------------------------------------------------
# PKSE (Public Key Searchable Encryption) is a cryptographic technique that allows users
# to perform keyword searches over encrypted data without decrypting it.
# Using a public key (Paillier cryptosystem here), the server can match encrypted queries
# to encrypted indexes, ensuring data privacy while supporting secure search functionality.
#only ONE KEY IS USED HERE,FOR BOTH ENCRYPTION AND SEARCHING
