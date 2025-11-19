def hill_encrypt(msg, key):
    msg = msg.upper().replace(' ', '')
    if len(msg)%2: msg += 'X'
    res = ''
    for i in range(0, len(msg), 2):
        a, b = ord(msg[i])-65, ord(msg[i+1])-65
        c1 = (key[0]*a + key[1]*b)%26
        c2 = (key[2]*a + key[3]*b)%26
        res += chr(c1+65) + chr(c2+65)
    return res

print(hill_encrypt("We live in an insecure world", [3,3,2,7]))
