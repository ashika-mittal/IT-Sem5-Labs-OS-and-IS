import socket

def client(message, host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode())
        local_hash = custom_hash(message)
        received = int(s.recv(1024).decode())
        print("Sent ciphertext:", message)
        print("Local hash:", local_hash)
        print("Server hash:", received)
        if local_hash == received:
            print("Integrity verified: Hashes match.")
        else:
            print("Integrity compromised: Hashes do not match.")

# Example usage:
if __name__ == "__main__":
    plaintext = "Secure Message"
    key = 15
    ciphertext = multiplicative_encrypt(plaintext, key)
    client(ciphertext)
