import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from Crypto.PublicKey import RSA
from utils import (
    generate_rsa_keys,
    decrypt_with_rsa,
    load_rsa_keys,
    encode,
    decode,
    send,
    receive,
)

PORT = 8765
IP = "localhost"
FORMAT = "utf-8"

generate_rsa_keys("server")
private_key, public_key = load_rsa_keys("server")
clients = dict()


async def secure_connection(websocket: ServerConnection):
    await websocket.send(encode(public_key.export_key()))
    client_secret_key_encrypted = await websocket.recv()

    client_secret_key = decrypt_with_rsa(
        decode(client_secret_key_encrypted), private_key
    )

    clients[websocket.id] = client_secret_key


async def serve(websocket: ServerConnection):
    await secure_connection(websocket)

    data = await receive(websocket, clients[websocket.id])
    print(data)
    await send("Welcome to my server", websocket, clients[websocket.id])


async def start_server():
    async with websockets.serve(serve, "localhost", 8765):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
