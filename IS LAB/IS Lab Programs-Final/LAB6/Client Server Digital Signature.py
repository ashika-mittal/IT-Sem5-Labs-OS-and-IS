import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

HOST = '127.0.0.1'
PORT = 65434

# ---------------- Generate RSA keys ----------------
# Alice's keys
alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
alice_public_key = alice_private_key.public_key()

# Bob's keys
bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_public_key = bob_private_key.public_key()

# ---------------- Utility functions for length-prefixed messages ----------------
def send_with_length(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')  # 4-byte header
    sock.sendall(length + data)

def recv_with_length(sock) -> bytes:
    length_bytes = sock.recv(4)
    if not length_bytes:
        return b''
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

# ---------------- Server Function ----------------
def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("\n[SERVER] Waiting for client...\n")
        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Connected by {addr}\n")

            # Receive message and signature
            message = recv_with_length(conn)
            signature = recv_with_length(conn)
            print("[SERVER] Message received:\n", message.decode(errors='ignore'), "\n")

            # Verify Alice's signature
            try:
                alice_public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("[SERVER] Verified Alice's signature ✅\n")
            except:
                print("[SERVER] Signature verification failed ❌\n")

            # Server signs a response
            response = b"Response from Bob"
            response_signature = bob_private_key.sign(
                response,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Send response and signature
            send_with_length(conn, response)
            send_with_length(conn, response_signature)
            print("[SERVER] Response sent with signature\n")

# ---------------- Client Function ----------------
def client():
    import time
    time.sleep(0.5)  # Slight delay to let server start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Client signs a message
        # NOTE: The message can be anything — a document, a string, or even a name.
        message = b"Legal Document: Agreement between Alice and Bob"
        alice_signature = alice_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Send message and signature
        send_with_length(s, message)
        send_with_length(s, alice_signature)
        print("[CLIENT] Message and signature sent\n")

        # Receive server's response and signature
        response = recv_with_length(s)
        response_signature = recv_with_length(s)
        print("[CLIENT] Response received:\n", response.decode(errors='ignore'), "\n")

        # Verify Bob's signature
        try:
            bob_public_key.verify(
                response_signature,
                response,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[CLIENT] Verified Bob's signature ✅\n")
        except:
            print("[CLIENT] Signature verification failed ❌\n")

# ---------------- Run both threads ----------------
server_thread = threading.Thread(target=server)
client_thread = threading.Thread(target=client)

server_thread.start()
client_thread.start()

server_thread.join()
client_thread.join()
