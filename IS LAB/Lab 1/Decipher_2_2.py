def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    shift = key
    for i, char in enumerate(plaintext):
        p = ord(char) - 65
        c = (p + shift) % 26
        ciphertext += chr(c + 65)
        shift = p
    return ciphertext

def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    plaintext = ""
    shift = key
    for char in ciphertext:
        c = ord(char) - 65
        p = (c - shift + 26) % 26
        plaintext += chr(p + 65)
        shift = p
    return plaintext

message = "the house is being sold tonight"
key = 7

encrypted = autokey_encrypt(message, key)
print("Encrypted message:", encrypted)

decrypted = autokey_decrypt(encrypted, key)
print("Decrypted message:", decrypted)
