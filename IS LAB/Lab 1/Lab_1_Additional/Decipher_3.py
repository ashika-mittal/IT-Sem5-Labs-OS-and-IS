def vigenere_encrypt(plaintext, keyword):
    result = ""
    keyword = keyword.upper()
    keyword_length = len(keyword)
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            p_val = ord(char) - ascii_offset
            k_val = ord(keyword[key_index % keyword_length]) - 65
            c_val = (p_val + k_val) % 26
            result += chr(c_val + ascii_offset)
            key_index += 1
        else:
            result += char  # Ignore non-alphabetic chars and keep as is
    return result

plaintext = "Life is full of surprises"
keyword = "HEALTH"

ciphertext = vigenere_encrypt(plaintext, keyword)
ciphertext
