import socket
import threading
import hashlib
import time

HOST = '127.0.0.1'
PORT = 65432

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            full_data = b''
            while True:
                part = conn.recv(1024)
                if not part:
                    break
                full_data += part
            print("Server received full message:", full_data.decode())
            hash_val = compute_hash(full_data)
            conn.sendall(hash_val.encode())
            print("Server sent hash back to client:", hash_val)

def client(message):
    parts = [message[i:i+10] for i in range(0, len(message), 10)]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for part in parts:
            s.sendall(part)
            time.sleep(0.1)  # simulate separate sends
        s.shutdown(socket.SHUT_WR)
        hash_received = s.recv(1024).decode()
        hash_local = compute_hash(message)
        print("\nClient received hash:", hash_received)
        print("Client local hash:   ", hash_local)
        if hash_received == hash_local:
            print("Integrity verified: The message is intact.")
        else:
            print("Integrity check failed: The message was altered.")

if __name__ == "__main__":
    message = b"This is a message sent in multiple parts."
    # Run server in a thread
    server_thread = threading.Thread(target=server, daemon=True)
    server_thread.start()
    time.sleep(1)  # Wait a moment for server to start
    client(message)
