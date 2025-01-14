from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from websockets.asyncio.connection import Connection
import base64


AES_KEY_BYTE_SIZE = 16
RSA_KEYS_SIZE = 2048
FORMAT = "utf-8"


def encode(data):
    return base64.b64encode(data).decode(FORMAT)


def decode(data):
    return base64.b64decode(data)


async def send(data, websocket: Connection, secret_key):
    encrypted_data = encrypt_data(data.encode(), secret_key)
    await websocket.send(encode(encrypted_data))


async def receive(websocket: Connection, secret_key):
    encrypted_data = await websocket.recv()
    data = decrypt_data(decode(encrypted_data), secret_key)

    return data.decode()


def generate_rsa_keys(server_name):
    key = RSA.generate(RSA_KEYS_SIZE)
    private_key = key.export_key()
    public_key = key.public_key().export_key()

    with open(f"{server_name}_private.pem", "wb") as private_file:
        private_file.write(private_key)

    with open(f"{server_name}_public.pem", "wb") as public_key_file:
        public_key_file.write(public_key)


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


def encrypt_with_rsa(message: str, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)


def decrypt_with_rsa(encrypted_message: str, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(encrypted_message)


def load_rsa_keys(server_name):
    with open(f"{server_name}_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    with open(f"{server_name}_public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())

    return private_key, public_key
