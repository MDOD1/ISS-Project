import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from utils import (
    sign_data,
    generate_asymmetric_keys,
    decode,
    encode,
)

PORT = 9000
IP = "localhost"
create_certificate_route = "create_certificate"

public_key, private_key = generate_asymmetric_keys()


async def create_certificate(websocket: ServerConnection):
    server_public_key = decode(await websocket.recv())
    certificate = sign_data(server_public_key, private_key)

    await websocket.send(encode(certificate))


async def serve(websocket: ServerConnection):
    path = websocket.request.path
    if path[1:] == create_certificate_route:
        await create_certificate(websocket)
    else:
        await websocket.send(encode(public_key))


async def start_server():
    async with websockets.serve(serve, IP, PORT):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
