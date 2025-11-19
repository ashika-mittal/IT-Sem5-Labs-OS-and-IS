matrix = [
    ['G', 'U', 'I', 'D', 'A'],
    ['N', 'C', 'E', 'B', 'F'],
    ['H', 'K', 'L', 'M', 'O'],
    ['P', 'Q', 'R', 'S', 'T'],
    ['V', 'W', 'X', 'Y', 'Z']
]

def find_position(letter):
    if letter == 'J': 
        letter = 'I'
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None

def preprocess(text):
    text = text.upper().replace(" ", "").replace("J", "I")
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i+1]
        else:
            b = 'X'
        if a == b:  # avoid double letters
            digraphs.append(a + 'X')
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    return digraphs

# Encryption
def playfair_encrypt(plaintext):
    digraphs = preprocess(plaintext)
    ciphertext = ""
    for pair in digraphs:
        r1, c1 = find_position(pair[0])
        r2, c2 = find_position(pair[1])

        if r1 == r2:  # same row
            ciphertext += matrix[r1][(c1+1) % 5] + matrix[r2][(c2+1) % 5]
        elif c1 == c2:  # same column
            ciphertext += matrix[(r1+1) % 5][c1] + matrix[(r2+1) % 5][c2]
        else:  # rectangle swap
            ciphertext += matrix[r1][c2] + matrix[r2][c1]
    return ciphertext


# ----------------- Test -----------------
message = "The key is hidden under the door pad"
cipher = playfair_encrypt(message)
print("Ciphertext:", cipher)
