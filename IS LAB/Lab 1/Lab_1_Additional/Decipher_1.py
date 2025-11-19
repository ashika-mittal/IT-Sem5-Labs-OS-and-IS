ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
possible_plaintexts = {}

def decipher(text, key):
    result = ""
    for char in text:
        if char in alphabet:
            idx = (alphabet.index(char) - key) % 26
            result += alphabet[idx]
        else:
            result += char
    return result

# Try keys close to 13
for key in range(10, 17):
    plaintext = decipher(ciphertext, key)
    possible_plaintexts[key] = plaintext
    print(f"Key {key}:", plaintext)

# The actual plaintext will be recognizable (meaningful English)
