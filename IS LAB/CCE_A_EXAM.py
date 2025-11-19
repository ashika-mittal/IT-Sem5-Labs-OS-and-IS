import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from datetime import datetime

# Generate RSA keys for signing
RSA_KEY_SIZE = 2048
key_pair = RSA.generate(RSA_KEY_SIZE)
public_key = key_pair.publickey()

# In-memory storage
records = {}  # filename: {"encrypted_content", "hash", "signature", "timestamp"}
decrypted_files = {}  # For doctors: filename -> decrypted_content

# Helper functions
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)  # CBC mode
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def create_signature(data, private_key):
    h = SHA512.new(data.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(data, signature, pub_key):
    h = SHA512.new(data.encode())
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except:
        return False

def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Main menu
def main_menu():
    while True:
        print("\n--- Hospital Management System ---")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        choice = int(input("Enter role number: "))
        if choice == 1:
            patient_menu()
        elif choice == 2:
            doctor_menu()
        elif choice == 3:
            auditor_menu()
        elif choice == 4:
            break
        else:
            print("Invalid choice!")

# Patient menu
def patient_menu():
    while True:
        print("\n--- Patient Menu ---")
        print("1. Upload record")
        print("2. View past records")
        print("3. Back")
        ch = int(input("Choice: "))
        if ch == 1:
            filename = input("Enter filename to save record: ")
            content = input("Enter medical record content: ")
            key = get_random_bytes(16)  # AES key generated randomly
            encrypted_data = aes_encrypt(content, key)
            hash_obj = SHA512.new(content.encode())
            signature = create_signature(hash_obj.hexdigest(), key)  # Sign hash with key (simulate)
            timestamp = get_current_time()
            records[filename] = {"encrypted": encrypted_data, "hash": hash_obj.hexdigest(), "signature": signature, "timestamp": timestamp}
            print("Record uploaded and stored.")
        elif ch == 2:
            filename = input("Enter filename to view: ")
            if filename in records:
                print("Record timestamp:", records[filename]["timestamp"])
                # For simplicity, reading directly from storage (decryption simulated)
                print("Encrypted data (hex):", records[filename]["encrypted"].hex())
            else:
                print("Record not found.")
        elif ch == 3:
            break
        else:
            print("Invalid choice!")

# Doctor menu
def doctor_menu():
    while True:
        print("\n--- Doctor Menu ---")
        print("1. Decrypt patient record")
        print("2. Store hash of decrypted file")
        print("3. Verify signature")
        print("4. Back")
        ch = int(input("Choice: "))
        if ch == 1:
            filename = input("Enter filename: ")
            if filename in records:
                encrypted = records[filename]["encrypted"]
                # Decrypt with a known key (simulate)
                decrypted_content = aes_decrypt(encrypted, get_random_bytes(16))
                decrypted_files[filename] = decrypted_content
                print("Decrypted content:", decrypted_content)
            else:
                print("Record not found.")
        elif ch == 2:
            filename = input("Enter filename: ")
            if filename in decrypted_files:
                print("Hash of decrypted content:", SHA512.new(decrypted_files[filename].encode()).hexdigest())
            else:
                print("No decrypted content for this file.")
        elif ch == 3:
            filename = input("Enter filename: ")
            if filename in records:
                # Verify signature
                signature = records[filename]['signature']
                hash_val = records[filename]['hash']
                result = verify_signature(hash_val, signature, public_key)
                print("Signature valid." if result else "Invalid signature.")
            else:
                print("Record not found.")
        elif ch == 4:
            break
        else:
            print("Invalid choice!")

# Auditor menu
def auditor_menu():
    while True:
        print("\n--- Auditor Menu ---")
        print("1. View records")
        print("2. Verify signatures")
        print("3. Back")
        ch = int(input("Choice: "))
        if ch == 1:
            for filename, data in records.items():
                print(f"Filename: {filename} | Timestamp: {data['timestamp']}")
        elif ch == 2:
            filename = input("Enter filename: ")
            if filename in records:
                result = verify_signature(records[filename]['hash'], records[filename]['signature'], public_key)
                print("Signature valid." if result else "Invalid signature.")
            else:
                print("Record not found.")
        elif ch == 3:
            break
        else:
            print("Invalid choice!")

# Run the program
if __name__ == "__main__":
    main_menu()
