import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from utils import (
    generate_asymmetric_keys,
    generate_aes_key,
    decrypt_with_rsa,
    encode,
    decode,
    verify_signature,
)
from apis import download_file, sign_up, log_in, upload_file, search

PORT = 8765
IP = "localhost"
CA_URI = "ws://localhost:9000/create_certificate"

public_key, private_key = generate_asymmetric_keys()
secret_key = generate_aes_key()
clients = dict()
certificate = None


async def create_certificate():
    global certificate
    async with websockets.connect(CA_URI) as client:
        await client.send(encode(public_key))
        certificate = decode(await client.recv())
        await client.close()


async def secure_connection(websocket: ServerConnection):
    global clients, certificate

    client_public_key = decode(await websocket.recv())
    await websocket.send(encode(public_key))
    await websocket.send(encode(certificate))

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
    client = clients[websocket.id]
    path = websocket.request.path[1:]

    if path == "sign_up":
        await sign_up(websocket, client, private_key)

    if path == "search_user_files":
        await search(websocket, client, private_key, secret_key)

    if path == "log_in":
        await log_in(websocket, client, private_key, secret_key)

    if path == "upload_file":
        await upload_file(websocket, client, private_key, secret_key)

    if path == "download_file":
        await download_file(websocket, client, private_key, secret_key)


async def start_server():
    await create_certificate()
    async with websockets.serve(serve, "localhost", PORT):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
