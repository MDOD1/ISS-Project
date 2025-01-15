from websockets.asyncio.server import ServerConnection
from utils import (
    convert_data_to_json,
    convert_json_to_data,
    decode,
    encode,
    send,
    receive,
)


async def upload_document(websocket: ServerConnection, client, private_key):
    pass
    # client_public_key, secret_key = client

    # request = await receive(websocket, secret_key, client_public_key)
    # data = convert_json_to_data(request)

    # file_id = data["file_id"]
    # print(f"Received request: {data["file_name"]}")

    # with open(f"./server_files/{file_name}", "wb") as file:
    #     file.write(file_bytes)

    # response = convert_data_to_json({"status": 200, "message": "Uploaded successfully"})
    # await send(response, websocket, secret_key, private_key)


async def upload_document(websocket: ServerConnection, client, private_key):
    client_public_key, secret_key = client

    request = await receive(websocket, secret_key, client_public_key)
    data = convert_json_to_data(request)

    file_name = data["file_name"]
    file_bytes = decode(data["file"])

    print(f"Received request: {data["file_name"]}")

    with open(f"./server_files/{file_name}", "wb") as file:
        file.write(file_bytes)

    response = convert_data_to_json({"status": 200, "message": "Uploaded successfully"})
    await send(response, websocket, secret_key, private_key)


async def sign_up(websocket: ServerConnection, client, private_key):
    client_public_key, secret_key = client

    request = await receive(websocket, secret_key, client_public_key)

    data = convert_json_to_data(request)
    print(f"Received request: {data}")

    response = convert_data_to_json({"status": 200, "message": "okay"})
    await send(response, websocket, secret_key, private_key)


async def log_in(websocket: ServerConnection, client):
    request = await receive(websocket, client)
    data = convert_json_to_data(request)
    print(f"Received request: {data}")
