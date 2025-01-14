import asyncio
import websockets
from websockets.asyncio.client import ClientConnection
from Crypto.PublicKey import RSA
import base64
from utils import (
    generate_aes_key,
    generate_asymmetric_keys,
    encrypt_with_rsa,
    sign_data,
    encrypt_data,
    decrypt_data,
    encode,
    decode,
    send,
    receive,
)

URI = "ws://localhost:8765"
FORMAT = "utf-8"
public_key, private_key = generate_asymmetric_keys()
my_secret_key = generate_aes_key()
server_public_key = None


async def secure_connection(client: ClientConnection):
    global server_public_key

    await client.send(encode(public_key))
    server_public_key = decode(await client.recv())

    encrypted_secret_key = encrypt_with_rsa(my_secret_key, server_public_key)
    signature = sign_data(encrypted_secret_key, private_key)

    await client.send(encode(signature))
    await client.send(encode(encrypted_secret_key))


async def start_client():
    async with websockets.connect(URI) as client:
        await secure_connection(client)

        await send("Where are you now?".encode(), client, my_secret_key, private_key)

        respone = await receive(client, (server_public_key, my_secret_key))
        print(respone)


if __name__ == "__main__":
    asyncio.run(start_client())
