def text_to_nums(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)


# ---------- Vigenere ----------
def vigenere_encrypt(plaintext, key):
    pt = text_to_nums(plaintext)
    k = text_to_nums(key)
    enc = [(pt[i] + k[i % len(k)]) % 26 for i in range(len(pt))]
    return nums_to_text(enc)

def vigenere_decrypt(ciphertext, key):
    ct = text_to_nums(ciphertext)
    k = text_to_nums(key)
    dec = [(ct[i] - k[i % len(k)]) % 26 for i in range(len(ct))]
    return nums_to_text(dec)


# ---------- Autokey ----------
def autokey_encrypt(plaintext, key):
    pt = text_to_nums(plaintext)
    enc = []
    current_key = key
    for p in pt:
        enc.append((p + current_key) % 26)
        current_key=p
    return nums_to_text(enc)

def autokey_decrypt(ciphertext, key):
    ct = text_to_nums(ciphertext)
    dec = []
    current_key = key
    for c in ct:
        p = (c -current_key) % 26
        dec.append(p)
        current_key=p
    return nums_to_text(dec)


# ----------------- Test -----------------
msg = "THEHOUSEISBEINGSOLDTONIGHT"

# Vigenere
vig_enc = vigenere_encrypt(msg, "DOLLARS")
vig_dec = vigenere_decrypt(vig_enc, "DOLLARS")

# Autokey
auto_enc = autokey_encrypt(msg, 7)
auto_dec = autokey_decrypt(auto_enc, 7)

print("Vigenere:", vig_enc, "->", vig_dec.lower())
print("Autokey :", auto_enc, "->", auto_dec.lower())
