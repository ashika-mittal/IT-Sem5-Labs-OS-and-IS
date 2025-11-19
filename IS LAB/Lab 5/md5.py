import hashlib

# Message to hash
message = "Hello, world!"

# Encode message to bytes, then create MD5 hash object
md5_hasher = hashlib.md5()
md5_hasher.update(message.encode('utf-8'))

# Get the hexadecimal MD5 digest
md5_hash = md5_hasher.hexdigest()

print(f"MD5 hash of '{message}' is: {md5_hash}")
