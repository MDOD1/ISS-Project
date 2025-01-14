import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from utils import (
    load_rsa_keys,
    encrypt_data,
    decrypt_data,
)

PORT = 8765
IP = "localhost"
FORMAT = "utf-8"

private_key, public_key = load_rsa_keys()
clients = dict()


async def secure_connection(websocket: ServerConnection):
    await websocket.send(public_key.export_key())


async def send(data, websocket: ServerConnection):
    encrypted_data = encrypt_data(data.encode(), clients[websocket.id])
    await websocket.send(encrypted_data)


async def receive(websocket: ServerConnection):
    encrypted_data = await websocket.recv()
    return decrypt_data(encrypted_data, clients[websocket.id]).decode()


async def serve(websocket: ServerConnection):
    await secure_connection(websocket)

    data = await receive(websocket)
    print(data)
    await send("Welcome to my server", websocket)


async def start_server():
    async with websockets.serve(serve, "localhost", 8765):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
