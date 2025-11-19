import socket

def multiplicative_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def multiplicative_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if 'A' <= char <= 'Z':
            num = ord(char) - ord('A') + 1
            cipher_num = (num * key) % 26
            if cipher_num == 0:
                cipher_num = 26
            cipher_char = chr(cipher_num + ord('A') - 1)
            ciphertext += cipher_char
    return ciphertext

def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF
    return hash_value

def server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f'Server listening on {host}:{port}')
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            data = conn.recv(1024).decode()
            print('Received ciphertext:', data)
            hash_val = custom_hash(data)
            conn.sendall(str(hash_val).encode())
            print('Sent hash value:', hash_val)

if __name__ == "__main__":
    server()
