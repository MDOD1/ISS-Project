import socket
import threading
from utils import (
    convert_json_to_data,
    convert_data_to_json,
    generate_asymmetric_keys,
    sign_data,
    encode,
    decode,
)

IP = "localhost"
PORT = 9000
FORMAT = "utf-8"
BUFFER_SIZE = 1024
public_key, private_key = generate_asymmetric_keys()


def create_certificate(request: dict):
    global private_key

    body = request.get("body")
    server_public_key = decode(body["public_key"])

    certificate = sign_data(server_public_key, private_key)
    response = {"header": {"status": 200}, "body": {"certificate": encode(certificate)}}

    return response


def handle_client(client_socket: socket.socket):
    global public_key

    try:
        request = client_socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
        if not request:
            return

        request_data = convert_json_to_data(request)
        header = request_data["header"]
        path = header["path"]
        print(path)

        if path == "/create_certificate":
            response = create_certificate(request_data)
        elif path == "/verify_certificate":
            response = {
                "header": {"status": 200},
                "body": {"public_key": encode(public_key)},
            }
        else:
            response = {"status": 404, "message": "Path not found."}

        client_socket.send(convert_data_to_json(response))
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f"CA Server running on {IP}:{PORT}")

    while True:
        client_socket, client_address = server.accept()
        print(f"New connection from {client_address}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()


if __name__ == "__main__":
    start_server()
