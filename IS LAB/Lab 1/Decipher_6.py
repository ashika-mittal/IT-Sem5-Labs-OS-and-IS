ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a = 5
b = 6
a_inv = 21
plaintext = ""

for c in ciphertext:
    if c.isalpha():
        y = ord(c.upper()) - ord('A')
        x = (a_inv * (y - b)) % 26
        plaintext += chr(x + ord('a'))
    else:
        plaintext += c

print(plaintext)
