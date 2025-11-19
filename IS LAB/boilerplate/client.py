import socket, pickle

# ===============================
# 🔧 ADD YOUR CRYPTO / ALGO CODE HERE
# ===============================

def your_algorithm_client():
    """
    Replace this function with your encryption / hashing / signing code.
    It should prepare the data you want to send to the server.
    Return a Python object (dict, list, string, etc.) to send.
    """
    print("\n[CLIENT] Example demo running...")

    # Example: simple message encryption placeholder
    msg = input("Enter a message to send: ")
    data = {"msg": msg}   # Replace with encrypted / hashed / signed data
    return data

# ===============================
# 🚀 CLIENT MAIN LOGIC
# ===============================

def run_client(host='127.0.0.1', port=65432):
    data = your_algorithm_client()
    payload = pickle.dumps(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(payload)
        print("\n✅ Data sent to server. Waiting for response...\n")
        response = s.recv(4096)
        if response:
            resp_data = pickle.loads(response)
            print("[CLIENT] Response from server:", resp_data)

if __name__ == "__main__":
    run_client()
