def decrypt_caesar(ciphertext, shift):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            p = (ord(c.upper()) - 65 - shift) % 26
            plaintext += chr(p + 65)
        else:
            plaintext += c
    return plaintext

# Given information
ciphertext1 = "CIW"
plaintext1  = "YES"

# Find the shift (from known plaintext attack)
shift = (ord(ciphertext1[0]) - ord(plaintext1[0])) % 26
print("Discovered Shift:", shift)

# Now decrypt the tablet text
ciphertext2 = "XVIEWYWI"
decrypted2 = decrypt_caesar(ciphertext2, shift)
print("Decrypted Text:", decrypted2)
