from sql_code.operations import insert_user, get_user, insert_file, get_files, get_file
from utils import (
    convert_data_to_json,
    verify_token,
    check_password,
    decode,
    encode,
    generate_token,
)


def search(request, secret_key):
    header = request["header"]
    body = request["body"]
    token = header.get("token")

    if not token:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    result = verify_token(token, secret_key)

    if not result:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    user_id = result["user_id"]
    is_staff = result["is_staff"]

    if not is_staff:
        return convert_data_to_json(
            {
                "header": {"status": 403},
                "body": {"message": "Forbidden"},
            }
        )

    user = get_user("nationality_number", body["nationality_number"])

    if not user:
        return convert_data_to_json(
            {
                "header": {"status": 404},
                "body": {"message": "User not Found!"},
            }
        )

    user_id, _, _ = user

    files = get_files("user_id", user_id)

    return convert_data_to_json(
        {
            "header": {"status": 200},
            "body": {"data": files},
        }
    )


def upload_file(request, secret_key):
    header = request["header"]
    body = request["body"]
    token = header.get("token")

    if not token:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    result = verify_token(token, secret_key)

    if not result:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    user_id = result["user_id"]
    is_staff = result["is_staff"]

    if is_staff:
        return convert_data_to_json(
            {
                "header": {"status": 403},
                "body": {"message": "Forbidden"},
            }
        )

    body["content"] = decode(body["content"])
    body["user_id"] = user_id

    insert_file(body)

    return convert_data_to_json(
        {
            "header": {"status": 200},
            "body": {"message": "Uploaded successfully"},
        }
    )


def sign_up(request, secret_key):
    body = request["body"]

    try:
        insert_user(body)

        response = {
            "header": {"status": 200},
            "body": {"message": "Signed up successfully"},
        }

    except Exception as e:
        response = {
            "haeader": {
                "status": 400,
            },
            "body": {
                "message": "This Nationality Number is already used!",
            },
        }

    return convert_data_to_json(response)


def log_in(request, secret_key):
    body = request["body"]

    user = get_user("nationality_number", body["nationality_number"])
    if user:
        id, stored_password, is_staff = user

    if user and check_password(body["password"], stored_password):
        token = generate_token({"user_id": id, "is_staff": is_staff}, secret_key)

        response = {
            "header": {
                "status": 200,
            },
            "body": {
                "token": token,
                "message": "Logged in Successfully!",
                "is_staff": is_staff,
            },
        }
    else:
        response = {
            "header": {
                "status": 404,
            },
            "body": {
                "message": "This user was not found!",
            },
        }

    return convert_data_to_json(response)


def download_file(request, secret_key):
    header = request["header"]
    body = request["body"]
    token = header.get("token")

    if not token:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    result = verify_token(token, secret_key)

    if not result:
        return convert_data_to_json(
            {
                "header": {"status": 401},
                "body": {"message": "Unauthenticated"},
            }
        )

    is_staff = result["is_staff"]

    if not is_staff:
        return convert_data_to_json(
            {
                "header": {"status": 403},
                "body": {"message": "Forbidden"},
            }
        )

    file = get_file(body["file_id"])

    if not file:
        return convert_data_to_json(
            {
                "header": {"status": 404},
                "body": {"message": "This File is not Found!"},
            }
        )

    file["content"] = encode(file["content"])

    return convert_data_to_json(
        {
            "header": {"status": 200},
            "body": {
                "file_name": file["file_name"],
                "content": file["content"],
            },
        }
    )
