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
token = None


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

    async with websockets.connect(url, max_size=10 * 1024 * 1024) as client:
        await secure_connection(client)
        await send(json, client, my_secret_key, private_key)
        return await receive(client, my_secret_key, server_public_key)


def sign_up():
    request = {
        "user_name": "me1",
        "phone_number": "1324232",
        "password": "hello",
        "nationality_number": "4",
        "is_staff": False,
        "birth_date": "2018-10-1",
    }
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/sign_up", json))
    result = convert_json_to_data(response)
    print(result)


def upload_file():
    global token

    file_path = "./documents/Information Security System.pdf"

    file_name = file_path.split("/")[-1]
    with open(file_path, "rb") as file:
        document = file.read()
    document = encode(document)

    request = {"token": token, "file_name": file_name, "content": document}
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/upload_file", json))
    result = convert_json_to_data(response)

    print(result)
    return result


def search():
    global token

    request = {"nationality_number": 1, "token": token}
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/search_user_files", json))
    result = convert_json_to_data(response)

    print(result)
    return result


def download_file():
    global token

    request = {"file_id": 4, "token": token}
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/download_file", json))
    result = convert_json_to_data(response)

    if result["status"] == 200:
        file = result["file"]

        file["content"] = decode(file["content"])
        result["file"] = file

        with open(f"./downloads/{file["file_name"]}", "wb") as f:
            f.write(file["content"])
    else:
        print(result)

    return result


def log_in():
    global token

    request = {
        "nationality_number": "2",
        "password": "hello",
    }
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/log_in", json))
    result = convert_json_to_data(response)
    token = result["token"]

    # print(token)
    return result


if __name__ == "__main__":
    log_in()
    # upload_file()
    # sign_up()
    # search()
    download_file()
