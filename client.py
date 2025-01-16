import asyncio
from utils import (
    convert_json_to_data,
    convert_data_to_json,
    encode,
    decode,
)
from https_request import connect

URI = "ws://localhost:8765"
token = None


def sign_up():
    request = {
        "user_name": "user2",
        "phone_number": "1324232",
        "password": "hello",
        "nationality_number": "40",
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

    request = {"nationality_number": "40", "token": token}
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
        "nationality_number": "20",
        "password": "hello",
    }
    json = convert_data_to_json(request)
    response = asyncio.run(connect(f"{URI}/log_in", json))
    result = convert_json_to_data(response)

    if result["status"] == 200:
        token = result["token"]

    # print(result)
    return result


if __name__ == "__main__":
    log_in()
    # upload_file()
    # sign_up()
    search()
    # download_file()
