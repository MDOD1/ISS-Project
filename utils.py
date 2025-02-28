from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import bcrypt
import socket
import base64
import jwt
import json
import bleach


AES_KEY_BYTE_SIZE = 32
RSA_KEYS_BYTE_SIZE = 2048
FORMAT = "utf-8"
BUFFER_SIZE = 1024


import html


def escape_output(data):
    if isinstance(data, dict):
        return {key: escape_output(value) for key, value in data.items()}
    elif isinstance(data, str):
        return html.escape(data)
    return data


def sanitize_input(data: dict):
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = bleach.clean(value, strip=True)

    return data


def generate_token(payload, secret_key):
    return jwt.encode(payload, secret_key, algorithm="HS256")


def verify_token(token, secret_key):
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None


def convert_data_to_json(data):
    return json.dumps(data).encode()


def convert_json_to_data(json_data):
    return json.loads(json_data)


def hash_data(data):
    return SHA256.new(data)


def encode(data):
    return base64.b64encode(data).decode(FORMAT)


def decode(encoded_data):
    return base64.b64decode(encoded_data)


def send(data, socket: socket.socket, secret_key: bytes, private_key: bytes):
    encrypted_request = encrypt_data(data, secret_key)
    signature = sign_data(encrypted_request, private_key)

    data = convert_data_to_json(
        {"signature": encode(signature), "data": encode(encrypted_request)}
    )
    data_size = len(data)
    socket.send(convert_data_to_json({"data_size": data_size}))

    message = socket.recv(BUFFER_SIZE).decode(FORMAT).strip()

    for i in range(0, data_size, BUFFER_SIZE):
        socket.send(data[i : i + BUFFER_SIZE])


def receive(socket: socket.socket, secret_key, public_key):
    request = socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
    request = convert_json_to_data(request)

    data_size = int(request["data_size"])
    socket.send(convert_data_to_json({"message": "Okay"}))

    data = b""
    total_received = 0
    while total_received < data_size:
        chunk = socket.recv(BUFFER_SIZE)
        data += chunk
        total_received += len(chunk)

    data = convert_json_to_data(data)

    signature = decode(data["signature"])
    encrypted_response = decode(data["data"])

    is_verified = verify_signature(encrypted_response, signature, public_key)
    if is_verified:
        response = decrypt_data(encrypted_response, secret_key)
        return convert_json_to_data(response)
    else:
        print("Data is corrupted")


def generate_asymmetric_keys():
    key = RSA.generate(RSA_KEYS_BYTE_SIZE)
    private_key = key.export_key()
    public_key = key.public_key().export_key()

    return public_key, private_key


def generate_aes_key():
    return get_random_bytes(AES_KEY_BYTE_SIZE)


def encrypt_data(message: bytes, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return cipher.iv + ciphertext


def decrypt_data(encrypted_message: str, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    return unpad(padded_message, AES.block_size)


def encrypt_with_rsa(message, key):
    key = RSA.import_key(key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)


def decrypt_with_rsa(encrypted_message: str, key):
    key = RSA.import_key(key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(encrypted_message)


def sign_data(data: bytes, private_key: bytes):
    key = RSA.import_key(private_key)
    hashed_data = hash_data(data)
    signature = pkcs1_15.new(key).sign(hashed_data)

    return signature


def verify_signature(data: bytes, signature: bytes, public_key: bytes):
    try:
        key = RSA.import_key(public_key)
        hashed_data = hash_data(data)
        pkcs1_15.new(key).verify(hashed_data, signature)
        return True
    except (ValueError, TypeError):
        return False


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def check_password(password, stored_hashed_password):
    return bcrypt.checkpw(password.encode("utf-8"), stored_hashed_password)
