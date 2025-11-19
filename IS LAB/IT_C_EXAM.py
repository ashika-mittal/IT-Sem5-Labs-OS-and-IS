from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Step 1: Generate RSA Key pair (Candidate and Election commission)
candidate_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
candidate_public_key = candidate_private_key.public_key()

commission_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
commission_public_key = commission_private_key.public_key()

# Step 2: AES Encryption
manifest = b'VoteManifest2025:CandidateX'
aes_key = os.urandom(16)  # AES-128
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
# Pad the manifest to block size (16 bytes)
padding_len = 16 - len(manifest) % 16
manifest_padded = manifest + bytes([padding_len] * padding_len)
ciphertext = encryptor.update(manifest_padded) + encryptor.finalize()

# AES key encrypted with commission's public RSA key
encrypted_aes_key = commission_public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Step 3: SHA-256 Hash of the Manifest
digest = hashes.Hash(hashes.SHA256())
digest.update(manifest)
manifest_hash = digest.finalize()

# Step 4: Candidate signs the Hash
signature = candidate_private_key.sign(
    manifest_hash,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Data to send (ciphertext, iv, encrypted_aes_key, signature, manifest_hash)

# Step 5: Election commission verifies everything:
# Decrypt AES key
decrypted_aes_key = commission_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
# Decrypt manifest
cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
decryptor = cipher.decryptor()
manifest_decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
manifest_decrypted = manifest_decrypted_padded[:-manifest_decrypted_padded[-1]]

# Hash again for verification
digest2 = hashes.Hash(hashes.SHA256())
digest2.update(manifest_decrypted)
manifest_hash2 = digest2.finalize()

# Verify signature
try:
    candidate_public_key.verify(
        signature,
        manifest_hash2,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print('Signature and hash verified, manifest untampered!')
except Exception:
    print('Hash/signature verification failed, manifest possibly tampered!')

# Tampering simulation
tampered_manifest = b'VoteManifest2025:CandidateY'
digest3 = hashes.Hash(hashes.SHA256())
digest3.update(tampered_manifest)
tampered_hash = digest3.finalize()

try:
    candidate_public_key.verify(
        signature,
        tampered_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print('Tampered manifest passed (unexpected)!')
except Exception:
    print('Tampered manifest detected, signature fail!')
