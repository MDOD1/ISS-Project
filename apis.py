from websockets.asyncio.server import ServerConnection
from sql_code.operations import insert_user, get_user, insert_file, get_files, get_file
from utils import (
    convert_data_to_json,
    convert_json_to_data,
    verify_token,
    check_password,
    decode,
    encode,
    generate_token,
    send,
    receive,
)


async def search(websocket: ServerConnection, client, private_key, secret_key):
    client_public_key, client_secret_key = client

    request = await receive(websocket, client_secret_key, client_public_key)
    data = convert_json_to_data(request)
    token = data["token"]

    if token:
        result = verify_token(token, secret_key)
        user_id = result["user_id"]
        is_staff = result["is_staff"]

    if not result or not is_staff:
        response = convert_data_to_json({"status": 403, "message": "Unauthorized"})
        await send(response, websocket, client_secret_key, private_key)
        await websocket.close()
        return

    user = get_user("nationality_number", data["nationality_number"])

    if not user:
        response = convert_data_to_json({"status": 404, "message": "User not Found"})
        await send(response, websocket, client_secret_key, private_key)
        await websocket.close()
        return

    user_id, _, _ = user

    files = get_files("user_id", user_id)
    response = convert_data_to_json({"status": 200, "data": files})
    await send(response, websocket, client_secret_key, private_key)


async def upload_file(websocket: ServerConnection, client, private_key, secret_key):
    client_public_key, client_secret_key = client

    request = await receive(websocket, client_secret_key, client_public_key)
    data = convert_json_to_data(request)
    token = data["token"]

    if token:
        result = verify_token(token, secret_key)
        user_id = result["user_id"]
        is_staff = result["is_staff"]

    if not result or is_staff:
        response = convert_data_to_json({"status": 403, "message": "Unauthorized"})
        await send(response, websocket, client_secret_key, private_key)
        await websocket.close()
        return

    data["content"] = decode(data["content"])
    data["user_id"] = user_id

    insert_file(data)

    response = convert_data_to_json({"status": 200, "message": "Uploaded successfully"})
    await send(response, websocket, client_secret_key, private_key)


async def sign_up(websocket: ServerConnection, client, private_key):
    client_public_key, client_secret_key = client

    request = await receive(websocket, client_secret_key, client_public_key)

    data = convert_json_to_data(request)

    try:
        insert_user(data)
        response = convert_data_to_json(
            {"status": 200, "message": "Signed up Successfully!"}
        )
    except Exception as e:
        response = convert_data_to_json(
            {"status": 400, "message": "This Nationality Number is already used!"}
        )

    await send(response, websocket, client_secret_key, private_key)


async def log_in(websocket: ServerConnection, client, private_key, secret_key):
    client_public_key, client_secret_key = client

    request = await receive(websocket, client_secret_key, client_public_key)
    data = convert_json_to_data(request)

    user = get_user("nationality_number", data["nationality_number"])

    if user:
        id, stored_password, is_staff = user

    if user and check_password(data["password"], stored_password):
        token = generate_token({"user_id": id, "is_staff": is_staff}, secret_key)

        response = {
            "status": "200",
            "data": {
                "message": "Logged in Successfully!",
                "is_staff": is_staff,
            },
            "token": token,
        }
    else:
        response = {"status": "404", "message": "This user was not found!"}

    await send(
        convert_data_to_json(response), websocket, client_secret_key, private_key
    )


async def download_file(websocket: ServerConnection, client, private_key, secret_key):
    client_public_key, client_secret_key = client

    request = await receive(websocket, client_secret_key, client_public_key)
    data = convert_json_to_data(request)
    token = data["token"]

    if token:
        result = verify_token(token, secret_key)
        is_staff = result["is_staff"]

    if not result or not is_staff:
        response = convert_data_to_json({"status": 403, "message": "Unauthorized"})
        await send(response, websocket, client_secret_key, private_key)
        await websocket.close()
        return

    file = get_file(data["file_id"])

    if not file:
        response = convert_data_to_json(
            {"status": 404, "message": "This File is not Found"}
        )
        await send(response, websocket, client_secret_key, private_key)
        await websocket.close()
        return

    file["content"] = encode(file["content"])

    response = convert_data_to_json(
        {"status": 200, "message": "Downloaded Successfully", "file": file}
    )
    await send(response, websocket, client_secret_key, private_key)
