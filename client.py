import asyncio
import websockets
from websockets.asyncio.client import ClientConnection
from utils import (
    generate_aes_key,
    generate_asymmetric_keys,
    convert_json_to_data,
    convert_data_to_json,
    encrypt_with_rsa,
    sign_data,
    verify_signature,
    encrypt_data,
    decrypt_data,
    encode,
    decode,
    send,
    receive,
)

URI = "ws://localhost:8765"
CA_URI = "ws://localhost:9000"


public_key, private_key = generate_asymmetric_keys()
my_secret_key = generate_aes_key()
server_public_key = None
ca_public_key = None


async def secure_connection(client: ClientConnection):
    global server_public_key, ca_public_key

    await client.send(encode(public_key))
    server_public_key = decode(await client.recv())
    certificate = decode(await client.recv())
    isVerified = verify_signature(server_public_key, certificate, ca_public_key)

    if not isVerified:
        print("This connection is not secure!")
        client.close()
        return

    encrypted_secret_key = encrypt_with_rsa(my_secret_key, server_public_key)
    signature = sign_data(encrypted_secret_key, private_key)

    await client.send(encode(signature))
    await client.send(encode(encrypted_secret_key))


async def connect(url, json):
    global ca_public_key, server_public_key, private_key
    async with websockets.connect(CA_URI) as client:
        ca_public_key = decode(await client.recv())
        await client.close()

    async with websockets.connect(url) as client:
        await secure_connection(client)
        await send(json, client, my_secret_key, private_key)
        return await receive(client, my_secret_key, server_public_key)


def sign_up():
    request = {"action": "get_user", "user_id": 1}
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/sign_up", json))
    result = convert_json_to_data(response)
    print(result)


def upload_document(document_path: str):
    file_name = document_path.split("/")[-1]
    with open(document_path, "rb") as file:
        document = file.read()

    document = encode(document)
    request = {"file_name": file_name, "file": document}
    json = convert_data_to_json(request)

    result = asyncio.run(connect(f"{URI}/upload_document", json))
    print(result)


if __name__ == "__main__":
    upload_document("./documents/Information Security System.pdf")
