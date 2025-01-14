import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
from utils import (
    generate_asymmetric_keys,
    convert_data_to_json,
    convert_json_to_data,
    decrypt_with_rsa,
    encode,
    decode,
    send,
    receive,
    sign_data,
    verify_signature,
)
from apis import sign_up, log_in, upload_document

PORT = 8765
IP = "localhost"
CA_URI = "ws://localhost:9000/create_certificate"

public_key, private_key = generate_asymmetric_keys()
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

    if path == "get_documents":
        pass

    if path == "log_in":
        await log_in(websocket, client)

    if path == "upload_document":
        await upload_document(websocket, client, private_key)

    if path == "download_document":
        pass


async def start_server():
    await create_certificate()
    async with websockets.serve(serve, "localhost", PORT):
        await asyncio.Future()


def main():
    asyncio.run(start_server())


if __name__ == "__main__":
    main()
