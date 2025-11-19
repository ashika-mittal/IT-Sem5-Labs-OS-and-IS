def encrypt(text, key):
    text = text.replace(" ", "").upper()
    result = ""
    for char in text:
        if char.isalpha():
            result += chr((ord(char) - 65 + key) % 26 + 65)
    return result

def decrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            result += chr((ord(char) - 65 - key) % 26 + 65)
    return result


key = 20
message = input("Enter the message to encrypt: ")
encrypted = encrypt(message, key)
print("Encrypted message:", encrypted)
choice = input("Do you want to decrypt the message? (yes/no): ").lower()
if choice == 'yes':
    decrypted = decrypt(encrypted, key)
    print("Decrypted message:", decrypted)
else:
    print("Okay, exiting.")
