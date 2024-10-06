import sys


def decrypt_file(input_path, output_path, key):
    """
    Reads the content of an encrypted file, applies XOR to decrypt the data,
    and saves it to a new file.

    Args:
        input_path (str): Path to the encrypted file.
        output_path (str): Path to save the decrypted file.
        key (hex): The XOR key (hex) used for decryption.

    Returns:
        None
    """
    try:
        # Read the encrypted file data
        with open(input_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Apply XOR to decrypt the data
        decrypted_data = bytes([byte ^ key for byte in encrypted_data])

        # Write the decrypted data to the output file
        with open(output_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted successfully! Saved to {output_path}")

    except Exception as e:
        print(f"Error decrypting file: {e}")


def main():
    # Parse command line arguments
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_file> <hex key> [output_file]")
        sys.exit(1)

    # Get the input file path
    input_file_path = sys.argv[1]

    # Convert the XOR key from hexadecimal string to int
    xor_key = int(sys.argv[2], 16)

    # Optionally get the output file path, default to "out.dmp"
    output_file_path = sys.argv[3] if len(sys.argv) > 3 else "out.dmp"

    # Perform decryption
    decrypt_file(input_file_path, output_file_path, xor_key)


if __name__ == "__main__":
    main()
