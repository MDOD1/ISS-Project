import socket
import threading
from utils import (
    convert_json_to_data,
    convert_data_to_json,
    generate_asymmetric_keys,
    generate_aes_key,
    receive,
    send,
    verify_signature,
    decrypt_with_rsa,
    encode,
    decode,
    sanitize_input,
    escape_output,
)
from apis import download_file, search, sign_up, log_in, upload_file

IP = "localhost"
PORT = 8000
PORT_CA = 9000
FORMAT = "utf-8"
BUFFER_SIZE = 1024 * 1024
public_key, private_key = generate_asymmetric_keys()
secret_key = generate_aes_key()
clients = dict()
certificate = None

routes = {
    "/sign_up": sign_up,
    "/log_in": log_in,
    "/upload_file": upload_file,
    "/search": search,
    "/download_file": download_file,
}


def create_certificate():
    global certificate, public_key, PORT_CA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((IP, PORT_CA))

        request_data = {
            "header": {"path": "/create_certificate"},
            "body": {"public_key": encode(public_key)},
        }

        request_json = convert_data_to_json(request_data)
        client_socket.send(request_json)

        response_json = client_socket.recv(BUFFER_SIZE)
        response_data = convert_json_to_data(response_json)
        body = response_data["body"]

        certificate = decode(body["certificate"])


def secure_connection(client_socket: socket.socket):
    global clients, certificate, private_key

    request = client_socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
    request_data = convert_json_to_data(request)
    body = request_data["body"]
    client_public_key = decode(body["public_key"])

    request = {
        "header": {},
        "body": {
            "public_key": encode(public_key),
            "certificate": encode(certificate),
        },
    }
    client_socket.send(convert_data_to_json(request))

    response = client_socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
    response_data = convert_json_to_data(response)
    body = response_data["body"]

    signature = decode(body["signature"])
    client_secret_key_encrypted = decode(body["secret_key"])

    is_authenticated = verify_signature(
        client_secret_key_encrypted,
        signature,
        client_public_key,
    )
    if is_authenticated:
        client_secret_key = decrypt_with_rsa(client_secret_key_encrypted, private_key)
        clients[id(client_socket)] = (client_public_key, client_secret_key)


def handle_client(client: socket.socket):
    global clients, public_key, secret_key

    try:
        secure_connection(client)
        client_public_key, client_secret_key = clients[id(client)]
        request = receive(client, client_secret_key, client_public_key)

        if not request:
            response = convert_data_to_json(
                {"body": {"message": "Something went Wrong"}}
            )
            send(response, client, client_secret_key, private_key)

        request["body"] = sanitize_input(request["body"])

        header = request["header"]
        path = header["path"]
        route_handler = routes.get(path)

        if not route_handler:
            response = convert_data_to_json(
                {"header": {"status": 404}, "body": {"message": "Not Found!"}}
            )
            send(response, client, client_secret_key, private_key)

        response = route_handler(request, secret_key)
        response["body"] = escape_output(response["body"])

        send(
            convert_data_to_json(response),
            client,
            client_secret_key,
            private_key,
        )
        client.close()
    finally:
        client.close()


def start_server():
    create_certificate()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f"Server running on {IP}:{PORT}")

    while True:
        client, client_address = server.accept()
        print(f"New connection from {client_address}")

        # Sequential
        # handle_client(client)

        # Parallel
        thread = threading.Thread(target=handle_client, args=(client,), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
