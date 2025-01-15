async def send_pdf(file_path):
    pdf_data = None
    with open(file_path, "rb") as file:
        pdf_data = file.read()  # Read the PDF file as binary data

    return pdf_data
