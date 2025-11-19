import socket
import threading
import time

# ---------------- Hash Function ----------------
def custom_hash(s: str) -> int:
    hash_val = 5381
    for ch in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(ch)
        hash_val &= 0xFFFFFFFF
    return hash_val

# ---------------- Server ----------------
def run_server():
    HOST, PORT = "127.0.0.1", 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("[SERVER] Listening on", HOST, PORT)

        conn, addr = s.accept()
        with conn:
            print("[SERVER] Connected by", addr)

            # Receive number of parts
            num_parts = int(conn.recv(1024).decode())
            conn.sendall(b"ACK")

            # Reassemble message
            message_parts = []
            for _ in range(num_parts):
                part = conn.recv(1024).decode()
                message_parts.append(part)
                conn.sendall(b"ACK")

            full_message = "".join(message_parts)
            print("[SERVER] Reassembled message:", full_message)

            # Compute hash
            hash_val = custom_hash(full_message)
            conn.sendall(str(hash_val).encode())

# ---------------- Client ----------------
def run_client(message):
    HOST, PORT = "127.0.0.1", 65432
    chunks = [message[i:i+10] for i in range(0, len(message), 10)]

    time.sleep(1)  # wait for server to start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Send number of parts
        s.sendall(str(len(chunks)).encode())
        s.recv(1024)  # wait for ACK

        # Send each part
        for part in chunks:
            s.sendall(part.encode())
            s.recv(1024)  # wait for ACK

        # Receive hash from server
        server_hash = int(s.recv(1024).decode())

        # Compute local hash
        local_hash = custom_hash(message)

        print("[CLIENT] Server hash:", server_hash)
        print("[CLIENT] Local hash: ", local_hash)
        if local_hash == server_hash:
            print("[CLIENT] ✅ Data integrity verified.")
        else:
            print("[CLIENT] ❌ Data corruption detected!")

# ---------------- Main ----------------
if __name__ == "__main__":
    # Message to send
    msg = "This is a long message that will be seen in multiple parts."

    # Start server in a background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Run client in main thread
    run_client(msg)
