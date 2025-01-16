import os
import glob

input_directory = "./current"
output_file_path = "./current/all.txt"

input_files = glob.glob(os.path.join(input_directory, "*.py"))
print(input_files)

with open(output_file_path, "w") as output_file:
    for file_path in input_files:
        file_name = os.path.basename(file_path)

        with open(file_path, "r") as input_file:
            output_file.write(f"Filename: {file_name}\n")
            output_file.write("========================================\n")
            content = input_file.read()
            output_file.write(content)
            output_file.write("\n")
            output_file.write("========================================\n")
