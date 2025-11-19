import socket
import threading
import time

def custom_hash(s: str) -> int:
    hash_val = 5381
    for ch in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(ch)
        hash_val &= 0xFFFFFFFF
    return hash_val


# --- Server Function ---
def run_server():
    HOST, PORT = "127.0.0.1", 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024).decode()
            print(f"[SERVER] Got data: {data}")
            server_hash = custom_hash(data)
            conn.sendall(str(server_hash).encode())


# --- Client Function ---
def run_client(message="hello world"):
    HOST, PORT = "127.0.0.1", 65432
    time.sleep(1)  # wait for server to start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[CLIENT] Sending: {message}")
        s.sendall(message.encode())
        server_hash = int(s.recv(1024).decode())
        local_hash = custom_hash(message)
        print(f"[CLIENT] Server hash: {server_hash}, Local hash: {local_hash}")
        print("[CLIENT] ✅ Verified" if local_hash == server_hash else "[CLIENT] ❌ Corrupted!")


if __name__ == "__main__":
    # Run server in a background thread
    threading.Thread(target=run_server, daemon=True).start()

    # Run client in main thread
    run_client("hello world")      # integrity OK
    run_client("tampered data")  # integrity FAIL
    # The server accepts one connection (s.accept()), handles it, and then exits.
    # When the second run_client("tampered data") runs, the server is already closed
    # → client can’t connect → ConnectionRefusedError.

