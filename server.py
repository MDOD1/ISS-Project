import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from utils import (
    generate_asymmetric_keys,
    decrypt_with_rsa,
    verify_signature,
    encode,
    decode,
    send,
    receive,
    sign_data,
    verify_signature,
)

PORT = 8765
IP = "localhost"
FORMAT = "utf-8"
CA_URI = "ws://localhost:9000/create_certificate"

public_key, private_key = generate_asymmetric_keys()
clients = dict()


async def create_certificate():
    async with websockets.connect(CA_URI) as client:
        await client.send(encode(public_key))
        respone = await client.recv()
        print(decode(respone))


async def secure_connection(websocket: ServerConnection):
    global clients

    client_public_key = decode(await websocket.recv())
    await websocket.send(encode(public_key))

    signature = decode(await websocket.recv())
    client_secret_key_encrypted = decode(await websocket.recv())

    is_authenticated = verify_signature(
        client_secret_key_encrypted,
        signature,
        client_public_key,
    )

    if is_authenticated:
        client_secret_key = decrypt_with_rsa(client_secret_key_encrypted, private_key)
        clients[websocket.id] = (client_public_key, client_secret_key)


async def serve(websocket: ServerConnection):
    await secure_connection(websocket)

    data = await receive(websocket, clients[websocket.id])
    print(data)
    await send(
        "Welcome to my server".encode(),
        websocket,
        clients[websocket.id][1],
        private_key,
    )


async def start_server():
    # await create_certificate()
    async with websockets.serve(serve, "localhost", 8765):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
