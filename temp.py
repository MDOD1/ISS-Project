import base64

# Binary data (e.g., encrypted AES key or message)
binary_data = b"\xfa\x13\xef\x01"

# Encode to Base64 (text-safe format)
encoded_data = base64.b64encode(binary_data).decode("utf-8")
print(encoded_data)

# Decode back to binary
decoded_data = base64.b64decode(encoded_data)
print(decoded_data)
