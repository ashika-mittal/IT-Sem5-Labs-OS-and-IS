# ------------------------------------------------------
# All Conversions: String ↔ Bytes ↔ Hex ↔ Integer
# ------------------------------------------------------

text = "Hello World"
print(f"Original String: {text}")

# -------------------------------
# 1️⃣ String → Bytes
# -------------------------------
b_data = text.encode('utf-8')
print(f"\nString → Bytes: {b_data}")

# -------------------------------
# 2️⃣ Bytes → String
# -------------------------------
s_data = b_data.decode('utf-8')
print(f"Bytes → String: {s_data}")

# -------------------------------
# 3️⃣ Bytes → Hex
# -------------------------------
hex_data = b_data.hex()
print(f"Bytes → Hex: {hex_data}")

# -------------------------------
# 4️⃣ Hex → Bytes
# -------------------------------
bytes_from_hex = bytes.fromhex(hex_data)
print(f"Hex → Bytes: {bytes_from_hex}")

# -------------------------------
# 5️⃣ String → Hex
# -------------------------------
hex_from_string = text.encode('utf-8').hex()
print(f"String → Hex: {hex_from_string}")

# -------------------------------
# 6️⃣ Hex → String
# -------------------------------
string_from_hex = bytes.fromhex(hex_from_string).decode('utf-8')
print(f"Hex → String: {string_from_hex}")

# -------------------------------
# 7️⃣ Bytes → Integer
# -------------------------------
int_from_bytes = int.from_bytes(b_data, byteorder='big')
print(f"Bytes → Integer: {int_from_bytes}")

# -------------------------------
# 8️⃣ Integer → Bytes
# -------------------------------
bytes_from_int = int_from_bytes.to_bytes((int_from_bytes.bit_length()+7)//8, byteorder='big')
print(f"Integer → Bytes: {bytes_from_int}")

# -------------------------------
# 9️⃣ Hex → Integer
# -------------------------------
int_from_hex = int(hex_data, 16)
print(f"Hex → Integer: {int_from_hex}")

# -------------------------------
# 10️⃣ Integer → Hex
# -------------------------------
hex_from_int = hex(int_from_hex)[2:]  # Remove '0x'
print(f"Integer → Hex: {hex_from_int}")
