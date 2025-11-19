def encrypt(plaintext,key):
    plaintext=plaintext.replace(' ','')
    key=key.upper()
    plaintext=plaintext.upper()
    ciphertext=""
    for i in range(0,len(plaintext)):
        cipher=((ord(plaintext[i])-ord('A'))+(ord(key[i%len(key)])-ord('A')))%26
        ciphertext+=chr(cipher+ord('A'))
    return ciphertext

def decrypt(ciphertext,key):
    plaintext=""
    key=key.upper()
    for i in range(0,len(ciphertext)):
        plain=((ord(ciphertext[i])-ord('A'))-(ord(key[i%len(key)])-ord('A')))%26
        plaintext+=chr(plain+ord('A'))
    return plaintext.lower()
msg="Life is full of surprises"
key="HEALTH"
ciphertetext=encrypt(msg,key)
print(ciphertetext)
plaintext=decrypt(ciphertetext,key)
print(plaintext)