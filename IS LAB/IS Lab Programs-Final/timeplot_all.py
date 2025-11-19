import time
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import matplotlib.pyplot as plt
import numpy as np

# -------------------------------
# Messages to test
# -------------------------------
messages = [
    "Hello World!",
    "Encryption performance test",
    "Short msg",
    "This is a longer message to test encryption times"
]
messages_bytes = [m.encode() for m in messages]

# -------------------------------
# Symmetric key encryption functions
# -------------------------------
def aes_encrypt_decrypt(message, key_size=16):
    key = b'K'*key_size  # simple key
    cipher = AES.new(key, AES.MODE_ECB)
    
    # encrypt
    start_enc = time.time()
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    enc_time = time.time() - start_enc
    
    # decrypt
    decipher = AES.new(key, AES.MODE_ECB)
    start_dec = time.time()
    decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)
    dec_time = time.time() - start_dec
    
    return enc_time*1000, dec_time*1000  # convert to milliseconds

def des_encrypt_decrypt(message):
    key = b'8bytekey'
    cipher = DES.new(key, DES.MODE_ECB)
    
    start_enc = time.time()
    ciphertext = cipher.encrypt(pad(message, DES.block_size))
    enc_time = time.time() - start_enc
    
    decipher = DES.new(key, DES.MODE_ECB)
    start_dec = time.time()
    decrypted = unpad(decipher.decrypt(ciphertext), DES.block_size)
    dec_time = time.time() - start_dec
    
    return enc_time*1000, dec_time*1000  # ms

# -------------------------------
# RSA encryption function
# -------------------------------
def rsa_encrypt_decrypt(message):
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    
    start_enc = time.time()
    ciphertext = cipher.encrypt(message)
    enc_time = time.time() - start_enc
    
    decipher = PKCS1_OAEP.new(key)
    start_dec = time.time()
    decrypted = decipher.decrypt(ciphertext)
    dec_time = time.time() - start_dec
    
    return enc_time*1000, dec_time*1000  # ms

# -------------------------------
# Measure times
# -------------------------------
algorithms = ['DES', 'AES-128', 'AES-192', 'AES-256', 'RSA']
enc_times = {algo: [] for algo in algorithms}
dec_times = {algo: [] for algo in algorithms}

for msg in messages_bytes:
    e,d = des_encrypt_decrypt(msg)
    enc_times['DES'].append(e)
    dec_times['DES'].append(d)
    
    e,d = aes_encrypt_decrypt(msg, 16)
    enc_times['AES-128'].append(e)
    dec_times['AES-128'].append(d)
    
    e,d = aes_encrypt_decrypt(msg, 24)
    enc_times['AES-192'].append(e)
    dec_times['AES-192'].append(d)
    
    e,d = aes_encrypt_decrypt(msg, 32)
    enc_times['AES-256'].append(e)
    dec_times['AES-256'].append(d)
    
    e,d = rsa_encrypt_decrypt(msg)
    enc_times['RSA'].append(e)
    dec_times['RSA'].append(d)

# -------------------------------
# Average times for plotting
# -------------------------------
avg_enc_times = [np.mean(enc_times[algo]) for algo in algorithms]
avg_dec_times = [np.mean(dec_times[algo]) for algo in algorithms]

x = np.arange(len(algorithms))
width = 0.35

plt.figure(figsize=(10,6))
plt.bar(x - width/2, avg_enc_times, width, label='Encryption')
plt.bar(x + width/2, avg_dec_times, width, label='Decryption', alpha=0.7)

plt.xticks(x, algorithms)
plt.ylabel("Average Time (ms)")
plt.title("Comparison of Symmetric and Asymmetric Encryption Times")
plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.yscale('log')
plt.show()
