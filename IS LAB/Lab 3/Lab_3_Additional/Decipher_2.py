from ecdsa import SECP256k1, SigningKey

# Generate ECC key pair (private and public key)
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.get_verifying_key()

message = b"Secure Transactions"

# Sign the message with the private key
signature = private_key.sign(message)

# Verify the signature with the public key
is_valid = public_key.verify(signature, message)

print("Signature valid:", is_valid)
