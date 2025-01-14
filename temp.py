from utils import generate_asymmetric_keys, sign_data, verify_signature

if __name__ == "__main__":
    # Generate RSA keys
    public_key, private_key = generate_asymmetric_keys()

    # Data to be signed
    message = b"Sign this secure message."

    # Signing the message
    signature = sign_data(message, private_key)
    print(f"Signature: {signature.hex()}")

    # Verifying the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Is the signature valid? {is_valid}")

    # Tampering with the message
    tampered_message = b"This is a tampered message."
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"Is the signature valid for tampered data? {is_valid_tampered}")
