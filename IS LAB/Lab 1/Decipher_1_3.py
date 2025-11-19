def mod_inverse(a, m=26):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i

def encrypt_affine(text, a, b):
    text = text.replace(" ", "").upper()
    return "".join(chr(((a * (ord(c) - 65) + b) % 26) + 65) for c in text if c.isalpha())

def decrypt_affine(text, a, b):
    a_inv = mod_inverse(a)
    return "".join(chr(((a_inv * ((ord(c) - 65) - b)) % 26) + 65) for c in text if c.isalpha())

a, b = 15, 20
message = input("Enter the message to encrypt: ")
encrypted = encrypt_affine(message, a, b)
print("Encrypted message:", encrypted)
if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
    print("Decrypted message:", decrypt_affine(encrypted, a, b))
else:
    print("Okay, exiting.")
