import asyncio
import websockets
from websockets.asyncio.client import ClientConnection
from Crypto.PublicKey import RSA
import base64
from utils import (
    generate_aes_key,
    encrypt_with_rsa,
    encrypt_data,
    decrypt_data,
    encode,
    decode,
    send,
    receive,
)

URI = "ws://localhost:8765"
FORMAT = "utf-8"
my_secret_key = generate_aes_key()


async def secure_connection(client: ClientConnection):
    encrypted_data = await client.recv()
    public_key = RSA.import_key(decode(encrypted_data))
    encrypted_secret_key = encrypt_with_rsa(my_secret_key, public_key)

    await client.send(encode(encrypted_secret_key))


async def start_client():
    async with websockets.connect(URI) as client:
        await secure_connection(client)
        await send("Where are you now?", client, my_secret_key)

        respone = await receive(client, my_secret_key)
        print(respone)


if __name__ == "__main__":
    asyncio.run(start_client())
