#PDA2 make a menu driven hospital management system
#1) Patient, 2) Doctor, 3) Auditor
#Patient:-
#1) Uploads a medical record ( they wanted with txt files input i think if u did with strings they gave marks as well but idk ) and encrypts it using AES.
#2) stores the Sign of the SHA512 hash of the medical record given by patient using RSA. #[ basically u hash the given input txt file, and then RSA on it ]
#3) View his old past records with time stamp.  [ what i did was he just enters the file name and i just open the file and read its lines to him ]
#Doctor:-
#1) Decrypts the patient's uploaded file. 
#2) Stores the SHA512 of the patient's file [ just hash the decrypted file and store it ]
#3) Verify the sign of the patient's file
#4) store the verification results
#Auditor:-
#1) Can see patients old records but cannot decrypt it.
#2) Can verify the signatures of the old records
#patient - upload medical record, encrypt file using AES, sign using SHA 512 with RSA, view past record with timestamps
#doctor - decryptes AES encrypted file using AES key, hashes decrypted file using sha 512, verifies rsa signature, stores signature verification results
#auditor - view past records, verifies rsa signatures

import os
import hashlib
from datetime import datetime

# --- Cryptography Imports ---
# You need to install the 'cryptography' library first:
# pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# --- Core Cryptography Logic ---

class CryptoManager:
    """Handles all cryptographic operations."""

    def __init__(self):
        self.backend = default_backend()

    # --- AES Symmetric Encryption ---
    def generate_aes_key(self):
        """Generates a secure 256-bit AES key."""
        return os.urandom(32)

    def encrypt_aes(self, data, key):
        """Encrypts data using AES-256 in CBC mode."""
        iv = os.urandom(16)  # Initialization Vector
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data to be a multiple of the block size
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt_aes(self, encrypted_data_with_iv, key):
        """Decrypts data using AES-256 in CBC mode."""
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return unpadded_data.decode('utf-8')

    # --- SHA-512 Hashing ---
    def hash_sha512(self, data):
        """Computes the SHA-512 hash of the data."""
        sha512 = hashlib.sha512()
        sha512.update(data.encode('utf-8'))
        return sha512.digest()

    # --- RSA Asymmetric Signature ---
    def generate_rsa_keys(self):
        """Generates a new RSA private/public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_hash(self, data_hash, private_key):
        """Signs a hash with an RSA private key."""
        signature = private_key.sign(
            data_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA512()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return signature

    def verify_signature(self, signature, data_hash, public_key):
        """Verifies an RSA signature against a hash and public key."""
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

# --- In-Memory Database Simulation ---
# In a real application, this would be a proper database.
patients = {}  # { "patient_name": {"private_key": ..., "public_key": ...} }
medical_records = {} # { "patient_name": [ { "record_id": ..., "timestamp": ..., ... } ] }

# --- Role-Based Menu Functions ---

def patient_menu(crypto):
    """Handles all actions for the Patient role."""
    patient_name = input("Enter your patient name: ")
    
    if patient_name not in patients:
        print(f"Welcome, new patient {patient_name}! Generating your secure keys...")
        private_key, public_key = crypto.generate_rsa_keys()
        patients[patient_name] = {"private_key": private_key, "public_key": public_key}
        medical_records[patient_name] = []
        print("Keys generated successfully.")

    while True:
        print(f"\n--- Patient Menu ({patient_name}) ---")
        print("1. Upload a new medical record")
        print("2. View my past records")
        print("3. Return to main menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            # 1. Get medical record from user
            record_data = input("Enter your medical record text:\n> ")
            
            # 2. Hash the original data
            record_hash = crypto.hash_sha512(record_data)
            
            # 3. Sign the hash with patient's private key
            patient_private_key = patients[patient_name]["private_key"]
            signature = crypto.sign_hash(record_hash, patient_private_key)
            
            # 4. Encrypt the data with a new AES key
            aes_key = crypto.generate_aes_key()
            encrypted_record = crypto.encrypt_aes(record_data, aes_key)

            # 5. Store the record
            record_id = len(medical_records[patient_name]) + 1
            new_record = {
                "record_id": record_id,
                "timestamp": datetime.now(),
                "encrypted_data": encrypted_record,
                "patient_signature": signature,
                "aes_key": aes_key, # In a real system, this would be managed more securely
                "doctor_hash": None,
                "verification_status": "Not Verified"
            }
            medical_records[patient_name].append(new_record)
            print(f"Record #{record_id} uploaded, encrypted, and signed successfully!")

        elif choice == '2':
            print("\n--- Your Past Medical Records ---")
            if not medical_records.get(patient_name):
                print("You have no records.")
            else:
                for record in medical_records[patient_name]:
                    print(f"  Record ID: {record['record_id']}")
                    print(f"  Timestamp: {record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                    print("-" * 20)
            input("Press Enter to continue...")

        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")


def doctor_menu(crypto):
    """Handles all actions for the Doctor role."""
    print("\n--- Doctor Menu ---")
    patient_name = input("Enter the name of the patient you want to access: ")
    if patient_name not in medical_records or not medical_records[patient_name]:
        print(f"No records found for patient '{patient_name}'.")
        return

    # Display records for the doctor to choose
    print(f"\n--- Records for {patient_name} ---")
    for rec in medical_records[patient_name]:
        print(f"ID: {rec['record_id']} | Timestamp: {rec['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | Status: {rec['verification_status']}")
    
    try:
        record_id_choice = int(input("Enter the Record ID to access: "))
        record_to_access = next((r for r in medical_records[patient_name] if r['record_id'] == record_id_choice), None)

        if not record_to_access:
            print("Invalid Record ID.")
            return

        # 1. Decrypt the patient's file
        aes_key = record_to_access['aes_key']
        decrypted_data = crypto.decrypt_aes(record_to_access['encrypted_data'], aes_key)
        print("\n[SUCCESS] Record decrypted successfully.")
        print(f"--- Decrypted Medical Record ---\n{decrypted_data}\n" + "-"*30)
        
        # 2. Store the SHA512 hash of the decrypted file
        doctor_calculated_hash = crypto.hash_sha512(decrypted_data)
        record_to_access['doctor_hash'] = doctor_calculated_hash
        print("[SUCCESS] Hash of decrypted content calculated and stored.")

        # 3. Verify the sign of the patient's file
        patient_public_key = patients[patient_name]["public_key"]
        patient_signature = record_to_access["patient_signature"]
        is_valid = crypto.verify_signature(patient_signature, doctor_calculated_hash, patient_public_key)

        # 4. Store the verification results
        if is_valid:
            record_to_access['verification_status'] = "Verified by Doctor"
            print("[SUCCESS] Patient's signature is VALID.")
        else:
            record_to_access['verification_status'] = "VERIFICATION FAILED"
            print("[FAILURE] WARNING! Patient's signature is NOT VALID. The record may have been tampered with!")
        
        input("\nPress Enter to return to the main menu.")

    except ValueError:
        print("Invalid input. Please enter a number for the Record ID.")


def auditor_menu(crypto):
    """Handles all actions for the Auditor role."""
    print("\n--- Auditor Menu ---")
    print("1. View all records (Encrypted View)")
    print("2. Verify a specific record's signature")
    print("3. Return to main menu")
    choice = input("Enter your choice: ")

    if choice == '1':
        print("\n--- All Patient Records (Auditor View) ---")
        if not medical_records:
            print("No records in the system.")
        for patient, records in medical_records.items():
            print(f"\nPatient: {patient}")
            print("=" * (len(patient) + 8))
            for rec in records:
                print(f"  Record ID: {rec['record_id']}")
                print(f"  Timestamp: {rec['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Encrypted Data (Snippet): {rec['encrypted_data'][:30].hex()}...")
                print(f"  Signature (Snippet): {rec['patient_signature'][:30].hex()}...")
                print(f"  Verification Status: {rec['verification_status']}")
                print("-" * 20)
        input("Press Enter to continue...")

    elif choice == '2':
        patient_name = input("Enter patient's name for verification: ")
        if patient_name not in medical_records:
            print("Patient not found.")
            return
        
        try:
            record_id = int(input(f"Enter record ID for {patient_name} to verify: "))
            record_to_verify = next((r for r in medical_records[patient_name] if r['record_id'] == record_id), None)
            
            if not record_to_verify:
                print("Record not found.")
                return

            if record_to_verify['doctor_hash'] is None:
                print("This record has not been decrypted and hashed by a doctor yet.")
                print("Auditor cannot verify until a doctor has processed it.")
                return

            print("Auditor is verifying the signature...")
            # The auditor uses the hash the DOCTOR calculated because they cannot decrypt the file themselves.
            # They trust the doctor's decryption and hash calculation.
            # The verification checks if the patient's signature matches the data the doctor saw.
            patient_public_key = patients[patient_name]["public_key"]
            is_valid = crypto.verify_signature(
                record_to_verify['patient_signature'],
                record_to_verify['doctor_hash'],
                patient_public_key
            )
            
            if is_valid:
                print("[AUDIT SUCCESS] The signature is valid for the content processed by the doctor.")
            else:
                print("[AUDIT FAILURE] The signature is INVALID. A discrepancy exists.")
            input("Press Enter to continue...")

        except ValueError:
            print("Invalid Record ID.")
            
    elif choice == '3':
        return
    else:
        print("Invalid choice.")


# --- Main Program Loop ---
def main():
    """The main entry point and menu driver for the system."""
    crypto_manager = CryptoManager()

    while True:
        print("\n===== Hospital Management System =====")
        print("Select your role:")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        
        role_choice = input("Enter choice: ")

        if role_choice == '1':
            patient_menu(crypto_manager)
        elif role_choice == '2':
            doctor_menu(crypto_manager)
        elif role_choice == '3':
            auditor_menu(crypto_manager)
        elif role_choice == '4':
            print("Exiting system. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 4.")


if __name__ == "__main__":
    main()



