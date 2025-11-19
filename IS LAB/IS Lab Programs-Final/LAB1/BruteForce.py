msg="NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

def decrypt(ciphertext):
    plaintext=""
    for k in range(6,20):
        plaintext = ""
        for c in ciphertext:
            if c.isalpha():
                plain=(ord(c)-ord('A')-k)%26
                plaintext+=chr(plain+ord('A'))
        print(plaintext.lower())

decrypt(msg)