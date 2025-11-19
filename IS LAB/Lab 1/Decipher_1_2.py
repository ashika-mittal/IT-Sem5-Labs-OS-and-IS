def mod_inverse(key, mod=26):
    for i in range(1, mod):
        if (key * i) % mod == 1:
            return i
    return None

def encrypt_multiplicative(text, key):
    text = text.replace(" ", "").upper()
    result = ""
    for char in text:
        if char.isalpha():
            result += chr(((ord(char) - 65) * key) % 26 + 65)
    return result

def decrypt_multiplicative(text, key):
    inv_key = mod_inverse(key, 26)
    if inv_key is None:
        return "Error: Key has no multiplicative inverse!"
    result = ""
    for char in text:
        if char.isalpha():
            result += chr(((ord(char) - 65) * inv_key) % 26 + 65)
    return result

key = 15
message = input("Enter the message to encrypt: ")
encrypted = encrypt_multiplicative(message, key)
print("Encrypted message:", encrypted)
choice = input("Do you want to decrypt the message? (yes/no): ").lower()
if choice == 'yes':
    decrypted = decrypt_multiplicative(encrypted, key)
    print("Decrypted message:", decrypted)
else:
    print("Okay, exiting.")
