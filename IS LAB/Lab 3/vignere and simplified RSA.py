def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key = key.upper()
    ciphertext = ""
    key_nums = [ord(k) - ord('A') for k in key]
    for i, char in enumerate(plaintext):
        if 'A' <= char <= 'Z':
            p_num = ord(char) - ord('A')
            k_num = key_nums[i % len(key)]
            c_num = (p_num + k_num) % 26
            ciphertext += chr(c_num + ord('A'))
    return ciphertext

def mod_exp(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

def rsa_sign(message_int, d, n):
    # Sign message integer with private key (d,n)
    return mod_exp(message_int, d, n)

def rsa_verify(signature, e, n):
    # Verify signature with public key (e,n)
    return mod_exp(signature, e, n)

# Sample small RSA keys (not secure, for demonstration)
e, d, n = 7, 23, 55  # Public exponent, private exponent, modulus

message = "HELLO WORLD"
key = "KEY"

# Encrypt with Vigenere
ciphertext = vigenere_encrypt(message, key)
print("Ciphertext:", ciphertext)

# Convert ciphertext to integer by concatenating ASCII values (simple demo)
msg_int = int(''.join(str(ord(c)) for c in ciphertext))

# Generate signature
signature = rsa_sign(msg_int, d, n)
print("Digital Signature:", signature)

# Verify signature
verified_msg_int = rsa_verify(signature, e, n)
print("Verified message integer:", verified_msg_int)

# Basic check
print("Signature valid:", verified_msg_int == msg_int)
