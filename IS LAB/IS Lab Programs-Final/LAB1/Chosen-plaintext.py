plaintext="abcdefghi"
ciphertext="CABDEHFGI"

def findKey(plaintext):
    plaintext=plaintext.upper()
    permute_key=[]
    i=0;j=0
    while i<len(plaintext):
        char=plaintext[i]
        for j in range(0,len(ciphertext)):
            if ciphertext[j]==char:
                permute_key.append(j+1)
                break
        i=i+1
    return permute_key

permute_key=findKey(plaintext)
print(permute_key)