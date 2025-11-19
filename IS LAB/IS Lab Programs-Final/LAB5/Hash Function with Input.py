def custom_hash(s: str) -> int:
    hash_val = 5381  # Initial hash value

    for ch in s:
        # Multiply by 33 and add ASCII of character
        hash_val = ((hash_val << 5) + hash_val) + ord(ch)

        # Keep it within 32-bit range
        hash_val &= 0xFFFFFFFF

    return hash_val


# Example usage
if __name__ == "__main__":

    text=input("Enter your name")
    print(f"Hash of '{text}' = {custom_hash(text)}")
