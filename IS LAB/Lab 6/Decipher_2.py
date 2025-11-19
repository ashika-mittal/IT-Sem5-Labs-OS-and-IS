from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    message_hash = hasher.finalize()
    signature = private_key.sign(
        message_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature, message_hash

def verify_signature(public_key, signature, message_hash):
    try:
        public_key.verify(
            signature,
            message_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def main():
    message = b"Digital Signature Lab 6 Complete Example"
    
    # Generate key pair for candidate
    private_key, public_key = generate_keys()
    
    # Sign the message
    signature, message_hash = sign_message(private_key, message)
    
    # Verification with correct message
    is_valid = verify_signature(public_key, signature, message_hash)
    if is_valid:
        print("Signature valid. Document is authentic.")
    else:
        print("Signature verification failed for original message!")
    
    # Tampering with the original message
    tampered_message = b"Digital Signature Lab 6 Complete Example (tampered)"
    
    # Hash tampered message
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(tampered_message)
    tampered_hash = hasher.finalize()
    
    # Verify signature against tampered hash (should fail)
    tampered_valid = verify_signature(public_key, signature, tampered_hash)
    if tampered_valid:
        print("Signature valid for tampered message! (Unexpected)")
    else:
        print("Signature verification failed for tampered message, tampering detected!")

if __name__ == "__main__":
    main()
