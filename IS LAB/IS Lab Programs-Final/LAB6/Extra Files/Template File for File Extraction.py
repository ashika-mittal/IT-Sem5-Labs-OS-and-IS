"""
Generic Cryptography Management System (Boilerplate)
----------------------------------------------------
Features:
1. Symmetric encryption (AES) - can be swapped with another algorithm
2. Asymmetric signature (RSA) - can be swapped with another algorithm
3. Hashing (SHA-512) - can be swapped with SHA-256, SHA-3, etc.
4. Data storage in text files with timestamps
5. Role-based access simulation (User, Verifier)
"""

import os
import hashlib
from datetime import datetime

# Cryptography Imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ---------------------------
# Cryptography Manager Class
# ---------------------------
class CryptoManager:
    """Handles encryption, decryption, hashing, signing, and signature verification."""

    def __init__(self):
        self.backend = default_backend()

    # --- Symmetric Encryption ---
    def generate_aes_key(self):
        """Generates a 256-bit AES key (change size or algorithm if needed)."""
        return os.urandom(32)  # For AES-128 use 16 bytes, AES-192 use 24 bytes

    def encrypt_aes(self, data, key):
        """Encrypts data using AES in CBC mode (can change algorithm/mode)."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt_aes(self, encrypted_data_with_iv, key):
        """Decrypts AES-encrypted data (can change algorithm/mode)."""
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode('utf-8')

    # --- Hashing ---
    def hash_sha512(self, data):
        """Hashes data using SHA-512 (can change to SHA-256, SHA3, etc.)."""
        sha512 = hashlib.sha512()
        sha512.update(data.encode('utf-8'))
        return sha512.digest()

    # --- RSA Asymmetric Key & Signature ---
    def generate_rsa_keys(self):
        """Generates RSA key pair (can change key size or algorithm)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # Change to 3072 or 4096 if needed
            backend=self.backend
        )
        return private_key, private_key.public_key()

    def sign_hash(self, data_hash, private_key):
        """Signs hash with RSA private key (can change padding algorithm)."""
        return private_key.sign(
            data_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA512()),  # Can change hash for MGF1
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()  # Can change to SHA-256
        )

    def verify_signature(self, signature, data_hash, public_key):
        """Verifies RSA signature (can change padding algorithm)."""
        try:
            public_key.verify(
                signature,
                data_hash,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA512()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except InvalidSignature:
            return False


# ---------------------------
# Data Storage Utilities
# ---------------------------
def save_record(user_name, record_data, filename="records.txt"):
    """Append a record with timestamp to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a") as f:
        f.write(f"{user_name} | {timestamp} | {record_data}\n")


def read_records(filename="records.txt"):
    """Read all records from the file."""
    if not os.path.exists(filename):
        print("No records found.")
        return
    with open(filename, "r") as f:
        for line in f:
            print(line.strip())


# ---------------------------
# Generic Role-Based Menu
# ---------------------------
def user_menu(crypto):
    """Generic User menu for data upload and signing."""
    user_name = input("Enter your username: ")

    # Generate RSA keys for the user
    private_key, public_key = crypto.generate_rsa_keys()
    print(f"RSA keys generated for {user_name}.")

    while True:
        print("\n--- User Menu ---")
        print("1. Upload & encrypt a record")
        print("2. View past records")
        print("3. Return to main menu")
        choice = input("Enter choice: ")

        if choice == '1':
            data = input("Enter data to store securely:\n> ")
            data_hash = crypto.hash_sha512(data)
            signature = crypto.sign_hash(data_hash, private_key)
            aes_key = crypto.generate_aes_key()
            encrypted_data = crypto.encrypt_aes(data, aes_key)

            # Store all info in file (encrypted data + signature + AES key in hex for demo)
            record_line = f"Encrypted:{encrypted_data.hex()} | Signature:{signature.hex()} | AESKey:{aes_key.hex()}"
            save_record(user_name, record_line)
            print("[SUCCESS] Record encrypted, signed, and saved.")

        elif choice == '2':
            print("\n--- All Records ---")
            read_records()

        elif choice == '3':
            break
        else:
            print("Invalid choice.")


def verifier_menu(crypto):
    """Generic Verifier menu to verify signatures (like Auditor/Doctor)."""
    print("\n--- Verifier Menu ---")
    filename = "records.txt"
    if not os.path.exists(filename):
        print("No records to verify.")
        return

    with open(filename, "r") as f:
        for i, line in enumerate(f, 1):
            print(f"{i}: {line.strip()}")

    record_no = int(input("Enter record number to verify: "))
    with open(filename, "r") as f:
        records = f.readlines()
        if 1 <= record_no <= len(records):
            line = records[record_no - 1].strip()
            # Extract signature (hex) from the line (assuming format used in user_menu)
            sig_part = [part for part in line.split("|") if "Signature:" in part][0]
            signature_hex = sig_part.split(":")[1]
            signature = bytes.fromhex(signature_hex)

            # For demo, hash data as placeholder (real case: would need decrypted data)
            print("Verification placeholder (replace with real decryption+hash logic).")
            print(f"Signature bytes: {signature[:20].hex()}... (truncated)")
        else:
            print("Invalid record number.")


# ---------------------------
# Main Driver
# ---------------------------
def main():
    crypto_manager = CryptoManager()

    while True:
        print("\n=== Generic Cryptography System ===")
        print("1. User (upload/encrypt/sign data)")
        print("2. Verifier (verify signatures)")
        print("3. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            user_menu(crypto_manager)
        elif choice == '2':
            verifier_menu(crypto_manager)
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
