ciphertext = "XVIEWYWI"
key = (ord('C') - ord('Y')) % 26
plaintext = ""

for c in ciphertext:
    if c.isalpha():
        base = ord('A')
        shifted = (ord(c.upper()) - base - key) % 26 + base
        plaintext += chr(shifted)
    else:
        plaintext += c

print(plaintext.lower())
