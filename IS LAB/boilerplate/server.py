import socket, pickle

# ===============================
# 🔧 ADD YOUR CRYPTO / ALGO CODE HERE
# ===============================

def your_algorithm_server(received_data):
    """
    Replace this with your decryption / verification / computation logic.
    Takes the object received from client.
    Returns a response object to send back.
    """
    print("\n[SERVER] Example demo running...")
    msg = received_data.get("msg", "No message received")
    print("[SERVER] Received message:", msg)

    # Example placeholder response
    response = {"status": "OK", "processed_msg": msg.upper()}
    return response

# ===============================
# 🚀 SERVER MAIN LOGIC
# ===============================

def run_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"🔐 Server running on {host}:{port} ...")

        conn, addr = s.accept()
        print("💡 Connected by", addr)
        data = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        if not data:
            print("❌ No data received.")
            return

        received_data = pickle.loads(data)
        print("[SERVER] Data received successfully.")

        response_data = your_algorithm_server(received_data)

        # Send response back to client
        conn.sendall(pickle.dumps(response_data))
        print("[SERVER] Response sent successfully.")
        conn.close()

if __name__ == "__main__":
    run_server()
