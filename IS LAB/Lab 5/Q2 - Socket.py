import socket

# Custom hash function as defined earlier
def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF
    return hash_value

def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f'Server listening on {host}:{port}')

        conn, addr = s.accept()
        with conn:
            print(f'Connected by {addr}')
            data = conn.recv(1024).decode()
            print('Received data:', data)
            
            # Compute hash of received data
            data_hash = custom_hash(data)

            # Send the hash back to client for verification
            conn.sendall(str(data_hash).encode())
            print('Sent hash:', data_hash)

if __name__ == "__main__":
    start_server()
