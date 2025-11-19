from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

# Generate RSA keys for a subsystem
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

# RSA encryption with recipient's public key
def rsa_encrypt(pub_key, data):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data)

# RSA decryption with own private key
def rsa_decrypt(priv_key, data):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(data)

# Diffie-Hellman key generation and shared secret computation (using small prime for demo)
def diffie_hellman():
    p = 23  # small prime for demo
    g = 5   # generator
    a = 6   # private key subsystem A
    b = 15  # private key subsystem B
    A = pow(g, a, p)
    B = pow(g, b, p)
    secret_A = pow(B, a, p)
    secret_B = pow(A, b, p)
    assert secret_A == secret_B
    return secret_A

# AES encryption and decryption
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ct_bytes

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

# Simulate communication
def main():
    # Generate RSA keys for two systems: Finance and HR
    priv_fin, pub_fin = generate_rsa_keys()
    priv_hr, pub_hr = generate_rsa_keys()
    
    # Diffie-Hellman shared secret
    shared_secret = diffie_hellman()
    
    # Derive AES key from shared secret
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    
    # Finance encrypts a message for HR
    message = "Financial report Q3"
    iv, encrypted_msg = aes_encrypt(aes_key, message)
    
    # HR decrypts the message
    decrypted_msg = aes_decrypt(aes_key, iv, encrypted_msg)
    
    print("Original message:", message)
    print("Encrypted (bytes):", encrypted_msg)
    print("Decrypted message:", decrypted_msg)

if __name__ == "__main__":
    main()
