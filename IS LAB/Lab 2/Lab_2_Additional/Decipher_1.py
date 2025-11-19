from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import os
import time
import matplotlib.pyplot as plt

# Accept user message
message = input("Enter the message to encrypt: ")

# Generate Keys
key_des = b'8bytekey'  # 8-byte key for DES
key_aes_128 = os.urandom(16)
key_aes_192 = os.urandom(24)
key_aes_256 = os.urandom(32)

modes = ['ECB', 'CBC', 'CFB', 'OFB']
results = {}

def encrypt_des(mode, key, message):
    iv = os.urandom(8)
    cipher_modes = {'ECB': DES.MODE_ECB,
                    'CBC': DES.MODE_CBC,
                    'CFB': DES.MODE_CFB,
                    'OFB': DES.MODE_OFB}
    cipher = DES.new(key, cipher_modes[mode], iv=iv if mode != 'ECB' else None)
    return cipher.encrypt(pad(message.encode(), DES.block_size))

def encrypt_aes(mode, key, message):
    iv = os.urandom(16)
    cipher_modes = {'ECB': AES.MODE_ECB,
                    'CBC': AES.MODE_CBC,
                    'CFB': AES.MODE_CFB,
                    'OFB': AES.MODE_OFB}
    cipher = AES.new(key, cipher_modes[mode], iv=iv if mode != 'ECB' else None)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

# Measure and plot
for algo in ['DES', 'AES-128', 'AES-192', 'AES-256']:
    results[algo] = []
    for mode in modes:
        start_time = time.time()
        if 'DES' == algo:
            encrypt_des(mode, key_des, message)
        elif 'AES-128' == algo:
            encrypt_aes(mode, key_aes_128, message)
        elif 'AES-192' == algo:
            encrypt_aes(mode, key_aes_192, message)
        else:
            encrypt_aes(mode, key_aes_256, message)
        results[algo].append(time.time() - start_time)

# Plot the results
for algo in results:
    plt.plot(modes, results[algo], label=algo)
plt.xlabel('Mode of Operation')
plt.ylabel('Time (seconds)')
plt.title('Encryption Time for Different Modes and Algorithms')
plt.legend()
plt.show()
