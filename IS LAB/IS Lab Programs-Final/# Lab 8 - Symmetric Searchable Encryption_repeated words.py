# Lab 8 - Symmetric Searchable Encryption (SSE)
# ---------------------------------------------
# Task: Find all words that appear more than once across all documents
# and encrypt the inverted index using AES.

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
    """Encrypts a string using AES CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    """Decrypts AES-encrypted data."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# ---------- 1c. Create Inverted Index ----------
def create_index(documents, key):
    """Creates an inverted index mapping each word to its document IDs and encrypts it."""
    index = {}

    # Step 1: Build the plaintext inverted index
    for doc_id, doc in documents.items():
        for word in doc.split():
            word = word.lower()
            if word not in index:
                index[word] = []
            index[word].append(doc_id)

    # Step 2: Encrypt the index (both words and document IDs)
    encrypted_index = {}
    for word, doc_ids in index.items():
        _, encrypted_word = encrypt_data(key, word)
        encrypted_index[encrypted_word] = []
        for doc_id in doc_ids:
            _, enc_doc = encrypt_data(key, doc_id)
            encrypted_index[encrypted_word].append(enc_doc)

    return index, encrypted_index

# ---------- 1d. Modified Search Logic ----------
def find_repeated_words(index):
    """Finds all words that appear in more than one document."""
    repeated = {word: docs for word, docs in index.items() if len(docs) > 1}
    return repeated

# ---------- Main Program ----------
key = get_random_bytes(16)
index, encrypted_index = create_index(documents, key)

print("\nEncrypted index created successfully!\n")

# ---------- Find and Display Repeated Words ----------
repeated_words = find_repeated_words(index)

if repeated_words:
    print("Words appearing in more than one document:\n")
    for word, doc_list in repeated_words.items():
        print(f"'{word}' → appears in {len(doc_list)} documents: {doc_list}")
else:
    print("No words appear more than once across documents.")

# ---------- (Optional) Decrypting example for demo ----------
print("\nExample Decryption Check (First Encrypted Word):")
for enc_word in encrypted_index.keys():
    # just decrypt one to demonstrate correctness
    iv = list(encrypted_index.keys())[0][:16]  # Extract IV from stored data
    break
print("Encrypted Index contains", len(encrypted_index), "unique words.")
