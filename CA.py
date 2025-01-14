import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from utils import (
    generate_asymmetric_keys,
    encrypt_with_rsa,
    hash_data,
    decode,
    encode,
    encrypt_data,
    decrypt_data,
)

PORT = 9000
IP = "localhost"
FORMAT = "utf-8"

public_key, private_key = generate_asymmetric_keys()
servers = dict()


async def create_certificate(websocket: ServerConnection):
    server_public_key = await websocket.recv()
    key = RSA.import_key(key)
    cipher = PKCS1_OAEP.new(key)
    print(server_public_key)
    hashed_server_public_key = hash_data(decode(server_public_key))
    cipher.encrypt(hashed_server_public_key)

    # server_public_key_encrypted = encrypt_with_rsa(
    #     hashed_server_public_key, private_key
    # )

    # await websocket.send(encode(server_public_key_encrypted))


async def serve(websocket: ServerConnection):
    path = websocket.request.path
    if path[1:] == "create_certificate":
        await create_certificate(websocket)


async def start_server():
    async with websockets.serve(serve, IP, PORT):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
