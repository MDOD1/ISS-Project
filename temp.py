# import os
# import glob

# input_directory = "./current"
# output_file_path = "./current/all.txt"

# input_files = glob.glob(os.path.join(input_directory, "*.py"))
# print(input_files)

# with open(output_file_path, "w") as output_file:
#     for file_path in input_files:
#         file_name = os.path.basename(file_path)

#         with open(file_path, "r") as input_file:
#             output_file.write(f"Filename: {file_name}\n")
#             output_file.write("========================================\n")
#             content = input_file.read()
#             output_file.write(content)
#             output_file.write("\n")
#             output_file.write("========================================\n")


# ====================================================================================
import threading
import os


def run_client():
    os.system("python client.py")


for _ in range(4):
    threading.Thread(target=run_client).start()
# ====================================================================================


# import socket
# from utils import encode, decode

# IP = "localhost"
# PORT = 9000


# def send_request(route, data):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.connect((IP, PORT))

#         request = f"{route} {data}"
#         client_socket.send(request.encode("utf-8"))

#         response = client_socket.recv(1024).decode("utf-8")
#         return response
