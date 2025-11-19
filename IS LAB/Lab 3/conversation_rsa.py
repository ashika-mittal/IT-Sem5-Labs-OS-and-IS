from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- Key Generation ---
# Each client generates its own RSA key pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

# --- Encryption/Decryption Functions ---
def rsa_encrypt(message, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(message.encode())

def rsa_decrypt(ciphertext, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext).decode()

# --- Simulating Two Clients ---
# Client A and Client B generate their RSA keys
privA, pubA = generate_rsa_keys()
privB, pubB = generate_rsa_keys()

# Suppose Client A wants to send "HELLO B" to Client B
message_A_to_B = "HELLO B"
print("Client A original message:", message_A_to_B)

# Client A encrypts using Client B's public key
encrypted_A_to_B = rsa_encrypt(message_A_to_B, pubB)
print("Encrypted message (hex):", encrypted_A_to_B.hex())

# Client B receives and decrypts using B's private key
decrypted_B = rsa_decrypt(encrypted_A_to_B, privB)
print("Client B decrypted message:", decrypted_B)
