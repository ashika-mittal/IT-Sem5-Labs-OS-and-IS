from Crypto.Util.number import bytes_to_long, long_to_bytes

# Given RSA parameters
n = 323
e = 5
d = 173

message_str = "Cryptographic Protocols"
message_bytes = message_str.encode('utf-8')
message_int = bytes_to_long(message_bytes)

# Encrypt using public key
cipher_int = pow(message_int, e, n)
print("Encrypted ciphertext (integer):", cipher_int)

# Decrypt using private key
plain_int = pow(cipher_int, d, n)
plain_bytes = long_to_bytes(plain_int)

# Decode decrypted bytes to string, ignoring errors if any
plain_str = plain_bytes.decode('utf-8', errors='ignore')
print("Decrypted message:", plain_str)
