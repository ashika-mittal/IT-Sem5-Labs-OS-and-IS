def custom_hash(input_string):
    hash_value = 5381  # initial hash value
    
    for char in input_string:
        # Multiply by 33 (left shift 5 + original) and add ASCII of char
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  
        # bitwise AND to keep 32-bits
        hash_value = hash_value & 0xFFFFFFFF  
    
    return hash_value

# Example usage
test_string = "Hello, Information Security Lab!"
hashed = custom_hash(test_string)
print(f"Input string: {test_string}")
print(f"Hash value: {hashed}")
