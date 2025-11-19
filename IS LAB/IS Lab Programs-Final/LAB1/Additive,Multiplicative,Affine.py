from Crypto.Util.number import inverse
# Helper functions
def text_to_nums(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)

# ---------- a) Additive Cipher ----------
def additive_encrypt(plaintext, key):
    nums = text_to_nums(plaintext)
    enc = [(x + key) % 26 for x in nums]
    return nums_to_text(enc)

def additive_decrypt(ciphertext, key):
    nums = text_to_nums(ciphertext)
    dec = [(x - key) % 26 for x in nums]
    return nums_to_text(dec)


# ---------- b) Multiplicative Cipher ----------
def mod_inverse(a, m):
    return inverse(a,m)

def multiplicative_encrypt(plaintext, key):
    nums = text_to_nums(plaintext)
    enc = [(x * key) % 26 for x in nums]
    return nums_to_text(enc)

def multiplicative_decrypt(ciphertext, key):
    inv = mod_inverse(key, 26)
    nums = text_to_nums(ciphertext)
    dec = [(x * inv) % 26 for x in nums]
    return nums_to_text(dec)


# ---------- c) Affine Cipher ----------
def affine_encrypt(plaintext, a, b):
    nums = text_to_nums(plaintext)
    enc = [(a * x + b) % 26 for x in nums]
    return nums_to_text(enc)

def affine_decrypt(ciphertext, a, b):
    inv_a = mod_inverse(a, 26)
    nums = text_to_nums(ciphertext)
    dec = [((x - b) * inv_a) % 26 for x in nums]
    return nums_to_text(dec)


# ----------------- Test -----------------
msg = "IAM LEARNING INFORMATION SECURITY"

# a) Additive
add_enc = additive_encrypt(msg, 20)
add_dec = additive_decrypt(add_enc, 20)

# b) Multiplicative
mul_enc = multiplicative_encrypt(msg, 15)
mul_dec = multiplicative_decrypt(mul_enc, 15)

# c) Affine
aff_enc = affine_encrypt(msg, 15, 20)
aff_dec = affine_decrypt(aff_enc, 15, 20)

print("Additive:", add_enc, "->", add_dec)
print("Multiplicative:", mul_enc, "->", mul_dec)
print("Affine:", aff_enc, "->", aff_dec)
