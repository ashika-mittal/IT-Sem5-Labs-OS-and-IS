import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import matplotlib.pyplot as plt
import numpy as np

# ----------------------------
# Test messages
# ----------------------------
messages = [
    "The quick brown fox jumps over the lazy dog",
    "AES encryption is secure",
    "Short msg",
    "This is a much longer message to test the performance of AES encryption",
    "1234567890" * 5
]

messages_bytes = [m.encode() for m in messages]

# ----------------------------
# Keys for algorithms
# ----------------------------
des_key = b"8bytekey"                     # DES key (8 bytes)
aes128_key = b"0123456789ABCDEF"          # AES-128 key (16 bytes)
aes192_key = b"0123456789ABCDEF01234567"  # AES-192 key (24 bytes)
aes256_key = b"0123456789ABCDEF0123456789ABCDEF"  # AES-256 key (32 bytes)

# ----------------------------
# Algorithms dictionary
# ----------------------------
algorithms = {
    "DES": (DES, des_key, DES.block_size),
    "AES-128": (AES, aes128_key, AES.block_size),
    "AES-192": (AES, aes192_key, AES.block_size),
    "AES-256": (AES, aes256_key, AES.block_size)
}

# ----------------------------
# Measure encryption & decryption time
# ----------------------------
def measure_times(cipher_cls, key, block_size, message):
    # Encrypt
    cipher_enc = cipher_cls.new(key, AES.MODE_ECB) if cipher_cls == AES else cipher_cls.new(key, DES.MODE_ECB)
    padded_msg = pad(message, block_size)
    start_enc = time.perf_counter()
    ciphertext = cipher_enc.encrypt(padded_msg)
    end_enc = time.perf_counter()
    enc_time = (end_enc - start_enc) * 1000  # ms

    # Decrypt
    cipher_dec = cipher_cls.new(key, AES.MODE_ECB) if cipher_cls == AES else cipher_cls.new(key, DES.MODE_ECB)
    start_dec = time.perf_counter()
    decrypted = unpad(cipher_dec.decrypt(ciphertext), block_size)
    end_dec = time.perf_counter()
    dec_time = (end_dec - start_dec) * 1000  # ms

    return enc_time, dec_time

# ----------------------------
# Collect results
# ----------------------------
enc_times = {alg: [] for alg in algorithms}
dec_times = {alg: [] for alg in algorithms}

for alg_name, (cls, key, block_size) in algorithms.items():
    for msg in messages_bytes:
        enc_t, dec_t = measure_times(cls, key, block_size, msg)
        enc_times[alg_name].append(enc_t)
        dec_times[alg_name].append(dec_t)

# ----------------------------
# Plotting
# ----------------------------
x = np.arange(len(messages))  # positions for each message
bar_width = 0.15

plt.figure(figsize=(12, 6))

for i, alg_name in enumerate(algorithms):
    plt.bar(x + i*bar_width, enc_times[alg_name], width=bar_width, label=f"{alg_name} Enc")
    plt.bar(x + i*bar_width, dec_times[alg_name], width=bar_width, bottom=enc_times[alg_name], alpha=0.5, label=f"{alg_name} Dec" if i==0 else "")

plt.xticks(x + bar_width*1.5, [f"Msg {i+1}" for i in range(len(messages))])
plt.ylabel("Time (ms)")
plt.title("Encryption & Decryption Times: DES vs AES")
plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.show()
