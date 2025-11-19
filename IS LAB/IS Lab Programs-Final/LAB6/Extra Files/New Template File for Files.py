"""
Cryptography Management System
----------------------------------------------------
This template highlights exactly where you can swap algorithms.
"""

import os
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# ===================================================
# CRYPTO MANAGER CLASS
# ===================================================
class CryptoManager:
    """Central class for encryption, hashing, and signatures."""

    def __init__(self):
        self.backend = default_backend()

    # ---------- SYMMETRIC (SWAPPABLE) ----------
    def generate_aes_key(self):
        # Swap here: os.urandom(32) → 16 bytes for AES-128 or 24 for AES-192
        return os.urandom(32)

    def encrypt_aes(self, data, key):
        # Swap here: algorithms.AES(key) → another symmetric algorithm
        # Swap here: modes.CBC(iv) → GCM, CTR, or other AES modes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt_aes(self, encrypted_data_with_iv, key):
        # Swap here: must match the algorithm/mode chosen in encrypt_aes
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode('utf-8')

    # ---------- HASHING (SWAPPABLE) ----------
    def hash_sha512(self, data):
        # Swap here: hashlib.sha512() → hashlib.sha256(), hashlib.sha3_512(), etc.
        sha512 = hashlib.sha512()
        sha512.update(data.encode('utf-8'))
        return sha512.digest()

    # ---------- ASYMMETRIC (SWAPPABLE) ----------
    def generate_rsa_keys(self):
        # Swap here: rsa.generate_private_key → ECC (Elliptic Curve) or ElGamal if library supports
        # Swap key_size=2048 → 3072 or 4096 for stronger RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        return private_key, private_key.public_key()

    def sign_hash(self, data_hash, private_key):
        # Swap here: PSS padding → PKCS1v15 padding
        # Swap hashes.SHA512() → hashes.SHA256(), hashes.SHA3_256(), etc.
        return private_key.sign(
            data_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA512()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

    def verify_signature(self, signature, data_hash, public_key):
        # Must match whatever algorithm and padding was used in sign_hash
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


# ===================================================
# STORAGE UTILITIES
# ===================================================
def save_record(user_name, record_data, filename="records.txt"):
    # Swap here: write to database, JSON, or CSV instead of plain text file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a") as f:
        f.write(f"{user_name} | {timestamp} | {record_data}\n")


def read_records(filename="records.txt"):
    # Swap here: adapt reading logic if storage format changes
    if not os.path.exists(filename):
        print("No records found.")
        return
    with open(filename, "r") as f:
        for line in f:
            print(line.strip())


# ===================================================
# ROLE MENUS
# ===================================================
def user_menu(crypto):
    # Swap here: add more roles (Student, Faculty, Admin) by copying this pattern
    user_name = input("Enter your username: ")
    private_key, public_key = crypto.generate_rsa_keys()

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
    # Swap here: extend to actually decrypt and re-hash before verifying
    print("\n--- Verifier Menu ---")
    filename = "records.txt"
    if not os.path.exists(filename):
        print("No records to verify.")
        return

    with open(filename, "r") as f:
        for i, line in enumerate(f, 1):
            print(f"{i}: {line.strip()}")

    record_no = int(input("Enter record number to inspect: "))
    with open(filename, "r") as f:
        records = f.readlines()
        if 1 <= record_no <= len(records):
            line = records[record_no - 1].strip()
            sig_part = [part for part in line.split("|") if "Signature:" in part][0]
            signature_hex = sig_part.split(":")[1]
            signature = bytes.fromhex(signature_hex)

            print("Signature extracted. Verification requires original data and hash.")
        else:
            print("Invalid record number.")


# ===================================================
# MAIN DRIVER
# ===================================================
def main():
    crypto_manager = CryptoManager()

    while True:
        print("\n=== Cryptography System ===")
        print("1. User")
        print("2. Verifier")
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
