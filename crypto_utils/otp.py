import os

def generate_key_file(input_file):
    """Generate a key file with the same length as the input file."""
    key_file = os.path.splitext(input_file)[0] + '.xkey'

    with open(input_file, 'rb') as f_in:
        data_length = len(f_in.read())

    key = os.urandom(data_length)  # Generate a key of the same length as the input file

    with open(key_file, 'wb') as f_out:
        f_out.write(key)

    return key_file

def xor_encrypt(input_file, key_file=None):
    """Perform XOR encryption using the key file."""
    if not key_file:
        key_file = generate_key_file(input_file)

    output_file = os.path.splitext(input_file)[0] + '.xc'

    file_extension = os.path.splitext(input_file)[1].encode('utf-8')
    file_extension_length = len(file_extension)

    with open(input_file, 'rb') as f_in, open(key_file, 'rb') as f_key, open(output_file, 'wb') as f_out:
        f_out.write(file_extension_length.to_bytes(1, 'big'))
        f_out.write(file_extension)
        while True:
            data = f_in.read(1024)  # Read data from input file in chunks
            key = f_key.read(len(data))  # Read corresponding key data

            if not data:
                break

            encrypted_data = bytes(b ^ k for b, k in zip(data, key))  # Perform XOR encryption
            f_out.write(encrypted_data)

        # Write the original file extension to the encrypted file
        file_extension = os.path.splitext(input_file)[1].encode('utf-8')
        f_out.write(file_extension)

    return output_file

def xor_decrypt(input_file, key_file):
    """Perform XOR decryption using the key file."""
    with open(input_file, 'rb') as f_in, open(key_file, 'rb') as f_key:
        # Read the length of the original file extension
        file_extension_length = int.from_bytes(f_in.read(1), 'big')
        # Read the original file extension
        original_extension = f_in.read(file_extension_length).decode('utf-8')

        decrypted_file = os.path.splitext(input_file)[0] + original_extension

        with open(decrypted_file, 'wb') as f_out:
            while True:
                data = f_in.read(1024)  # Read data from input file in chunks
                key = f_key.read(len(data))  # Read corresponding key data

                if not data:
                    break

                decrypted_data = bytes(b ^ k for b, k in zip(data, key))  # Perform XOR decryption
                f_out.write(decrypted_data)

    return decrypted_file

# Example usage:
#encrypted_file = xor_encrypt('example.txt')
#xor_decrypt("example.xc", "example.xkey")
