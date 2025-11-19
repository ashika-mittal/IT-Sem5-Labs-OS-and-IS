def encrypt(a):
    key = 20
    b=a%26
    c=chr(b+65+20)
    return c


print(encrypt(5))