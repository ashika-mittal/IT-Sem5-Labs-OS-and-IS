import os
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ========== ELGAMAL UTILITIES ==========
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def gen_elgamal_keys(p=30803, g=2):
    x = random.randint(1, p - 2)  # private key
    y = pow(g, x, p)              # public key
    return (p, g, y), x

def elgamal_encrypt(msg, pubkey):
    p, g, y = pubkey
    k = random.randint(1, p - 2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * msg) % p
    return a, b

def elgamal_decrypt(cipher, privkey, pubkey):
    a, b = cipher
    p, g, y = pubkey
    s = pow(a, privkey, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def elgamal_sign(msg_hash, privkey, pubkey):
    p, g, y = pubkey
    while True:
        k = random.randint(1, p - 2)
        if egcd(k, p - 1)[0] == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (msg_hash - privkey * r)) % (p - 1)
    return r, s

def elgamal_verify(msg_hash, signature, pubkey):
    r, s = signature
    p, g, y = pubkey
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, msg_hash, p)
    return v1 == v2

# ========== AES UTILITIES ==========
def aes_encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data.encode(), AES.block_size))

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ========== MAIN ROLES ==========
class Student:
    def __init__(self):
        self.aes_key = get_random_bytes(16)

    def encrypt_assignment(self, text):
        return aes_encrypt(text, self.aes_key)

class Faculty:
    def __init__(self, pubkey, privkey):
        self.pubkey = pubkey
        self.privkey = privkey

    def decrypt_assignment(self, ciphertext, aes_key):
        return aes_decrypt(ciphertext, aes_key)

    def give_marks(self, student_id, assignment_id, marks):
        marks_str = f"{student_id} {assignment_id} {marks}"
        marks_int = int.from_bytes(marks_str.encode(), "big")
        encrypted = elgamal_encrypt(marks_int, self.pubkey)
        h = int(hashlib.sha256(marks_str.encode()).hexdigest(), 16)
        sig = elgamal_sign(h, self.privkey, self.pubkey)
        return encrypted, sig, h

class Admin:
    def __init__(self, pubkey, privkey):
        self.pubkey = pubkey
        self.privkey = privkey

    def verify_and_display(self, encrypted, sig, h):
        if elgamal_verify(h, sig, self.pubkey):
            print("✔ Signature Verified")
            decrypted_int = elgamal_decrypt(encrypted, self.privkey, self.pubkey)
            decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, "big")
            print("Decrypted Marks:", decrypted_bytes.decode())
        else:
            print("✘ Signature Invalid")

# ========== MENU SYSTEM ==========
def main():
    # Generate ElGamal keys for Faculty/Admin
    pubkey, privkey = gen_elgamal_keys()
    student = Student()
    faculty = Faculty(pubkey, privkey)
    admin = Admin(pubkey, privkey)

    encrypted_assignment = None
    aes_key = None
    encrypted_marks = None
    sig = None
    h = None

    while True:
        print("\n===== ROLE BASED MENU =====")
        print("1. Student: Encrypt Assignment")
        print("2. Faculty: Decrypt & Give Marks")
        print("3. Admin: Verify & Display Marks")
        print("4. Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            text = input("Enter assignment text: ")
            encrypted_assignment = student.encrypt_assignment(text)
            aes_key = student.aes_key
            print("Assignment Encrypted & Sent to Faculty")

        elif choice == "2":
            if not encrypted_assignment:
                print("No assignment found. Student must send first.")
                continue
            dec = faculty.decrypt_assignment(encrypted_assignment, aes_key)
            print("Decrypted Assignment:", dec)
            sid = input("Enter Student ID: ")
            aid = input("Enter Assignment ID: ")
            marks = input("Enter Marks: ")
            encrypted_marks, sig, h = faculty.give_marks(sid, aid, marks)
            print("Marks Encrypted & Signed. Sent to Admin.")

        elif choice == "3":
            if not encrypted_marks:
                print("No marks found. Faculty must send first.")
                continue
            admin.verify_and_display(encrypted_marks, sig, h)

        elif choice == "4":
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
