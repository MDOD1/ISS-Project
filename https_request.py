import socket
from utils import (
    convert_json_to_data,
    convert_data_to_json,
    encode,
    decode,
    receive,
    send,
    verify_signature,
    encrypt_with_rsa,
    sign_data,
    generate_aes_key,
    generate_asymmetric_keys,
)

IP = "localhost"
CA_PORT = 9000
SERVER_PORT = 8000
BUFFER_SIZE = 1024
FORMAT = "utf-8"

public_key, private_key = generate_asymmetric_keys()
secret_key = generate_aes_key()

ca_public_key = None
server_public_key = None
token = None


def secure_connection(client_socket: socket.socket):
    global server_public_key, ca_public_key, secret_key, public_key

    request = {"header": {}, "body": {"public_key": encode(public_key)}}

    client_socket.send(convert_data_to_json(request))
    response = client_socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
    response_data = convert_json_to_data(response)

    body = response_data["body"]
    server_public_key = decode(body["public_key"])
    certificate = decode(body["certificate"])

    is_verified = verify_signature(server_public_key, certificate, ca_public_key)

    if not is_verified:
        print("This connection is not secure!")
        client_socket.close()

    encrypted_secret_key = encrypt_with_rsa(secret_key, server_public_key)
    signature = sign_data(encrypted_secret_key, private_key)
    request = {
        "header": {},
        "body": {
            "secret_key": encode(encrypted_secret_key),
            "signature": encode(signature),
        },
    }
    client_socket.send(convert_data_to_json(request))


def connect_to_ca(path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((IP, CA_PORT))

        request_data = {"header": {"path": path}}
        request_json = convert_data_to_json(request_data)
        client_socket.send(request_json)

        response_json = client_socket.recv(BUFFER_SIZE).decode(FORMAT).strip()
        return convert_json_to_data(response_json)


def connect(request):
    global secret_key, server_public_key, public_key, private_key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((IP, SERVER_PORT))
        secure_connection(client_socket)

        request = convert_data_to_json(request)
        send(request, client_socket, secret_key, private_key)
        return receive(client_socket, secret_key, server_public_key)


response = connect_to_ca("/verify_certificate")
body = response["body"]
ca_public_key = decode(body["public_key"])
