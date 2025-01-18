from utils import (
    encode,
    decode,
)
from https_request import connect
import time


def sign_up():
    request = {
        "header": {"path": "/sign_up"},
        "body": {
            "user_name": "<script>alert('XSS Attack!!!');</script>",
            "phone_number": "1324232",
            "password": "hello",
            "nationality_number": "50",
            "is_staff": False,
            "birth_date": "2018-10-1",
        },
    }
    response = connect(request)
    print(response)
    return response


def log_in():
    global token

    request = {
        "header": {
            "path": "/log_in",
        },
        "body": {
            "nationality_number": "20",
            "password": "hello",
        },
    }
    response = connect(request)
    header = response["header"]
    body = response["body"]

    if header["status"] == 200:
        token = body["token"]

    print(response)
    return response


def upload_file():
    global token
    file_path = "./documents/Information Security System.pdf"
    file_name = file_path.split("/")[-1]

    with open(file_path, "rb") as file:
        file = file.read()

    request = {
        "header": {"token": token, "path": "/upload_file"},
        "body": {
            "file_name": file_name,
            "content": encode(file),
        },
    }

    response = connect(request)
    print(response)
    return response


def search():
    global token

    request = {
        "header": {"token": token, "path": "/search"},
        "body": {
            "nationality_number": "30",
        },
    }

    response = connect(request)
    print(response)
    return response


def download_file():
    global token

    request = {
        "header": {"token": token, "path": "/download_file"},
        "body": {
            "file_id": 1,
        },
    }

    response = connect(request)

    header = response["header"]
    body = response["body"]

    if header["status"] == 200:
        file_name = body["file_name"]
        content = decode(body["content"])

        with open(f"./downloads/{file_name}", "wb") as f:
            f.write(content)
    else:
        print(response)

    return response


# sign_up()
log_in()
# upload_file()
# search()
# download_file()


# Test mutli_threading
# start_time = time.perf_counter()
# log_in()
# end_time = time.perf_counter()

# execution_time = end_time - start_time
# print(f"Execution time: {execution_time:.2f} seconds")
