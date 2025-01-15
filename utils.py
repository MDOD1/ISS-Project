from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from websockets.asyncio.connection import Connection
import base64
import json


AES_KEY_BYTE_SIZE = 16
RSA_KEYS_SIZE = 2048
FORMAT = "utf-8"


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


async def send(
    data: bytes, websocket: Connection, secret_key: bytes, private_key: bytes
):
    encrypted_data = encrypt_data(data, secret_key)
    signature = sign_data(encrypted_data, private_key)

    await websocket.send(encode(signature))
    await websocket.send(encode(encrypted_data))


async def receive(websocket: Connection, secret_key, public_key):
    signature = decode(await websocket.recv())
    encrypted_data = decode(await websocket.recv())

    if verify_signature(encrypted_data, signature, public_key):
        return decrypt_data(encrypted_data, secret_key)


def generate_asymmetric_keys():
    key = RSA.generate(RSA_KEYS_SIZE)
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
    iv = encrypted_message[:AES_KEY_BYTE_SIZE]
    ciphertext = encrypted_message[AES_KEY_BYTE_SIZE:]

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
