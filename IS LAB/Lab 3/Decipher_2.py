from ecdsa import SigningKey, NIST256p

message = b"Secure Transactions"
sk = SigningKey.generate(curve=NIST256p)
vk = sk.verifying_key

signature = sk.sign(message)
assert vk.verify(signature, message)

print("Message:", message.decode())
print("Signature:", signature.hex())
