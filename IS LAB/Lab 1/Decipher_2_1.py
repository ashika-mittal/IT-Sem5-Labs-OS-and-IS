def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key = key.upper()
    ciphertext = ""
    for i, char in enumerate(plaintext):
        p = ord(char) - 65
        k = ord(key[i % len(key)]) - 65
        c = (p + k) % 26
        ciphertext += chr(c + 65)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ""
    for i, char in enumerate(ciphertext):
        c = ord(char) - 65
        k = ord(key[i % len(key)]) - 65
        p = (c - k + 26) % 26
        plaintext += chr(p + 65)
    return plaintext

message = "the house is being sold tonight"
key = "dollars"

encrypted = vigenere_encrypt(message, key)
print("Encrypted message:", encrypted)

decrypted = vigenere_decrypt(encrypted, key)
print("Decrypted message:", decrypted)
