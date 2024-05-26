import os
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Constants
KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 7_234_082
CHUNK_SIZE = 64 * 1024  # 64KB

def derive_key(password, salt):
    """Derive a key from the password using PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_file(input_file, password):
    """Encrypt a file with a password using ChaCha20-Poly1305."""
    salt = get_random_bytes(SALT_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)
    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    # Get the file extension
    file_extension = os.path.splitext(input_file)[1].encode('utf-8')
    file_extension_length = len(file_extension)

    # Create the encrypted file name by replacing the original extension with .xc
    encrypted_file = os.path.splitext(input_file)[0] + '.xc'

    with open(input_file, 'rb') as f_in, open(encrypted_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(nonce)
        f_out.write(file_extension_length.to_bytes(1, 'big'))
        f_out.write(file_extension)
        f_out.write(b'\0' * TAG_SIZE)  # Placeholder for the tag

        while chunk := f_in.read(CHUNK_SIZE):
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            f_out.write(ciphertext)

        f_out.seek(SALT_SIZE + NONCE_SIZE + 1 + file_extension_length)  # Go back to the placeholder position
        f_out.write(tag)  # Write the actual tag

    print(f'File encrypted to {encrypted_file}')

def decrypt_file(encrypted_file, password):
    """Decrypt a file with a password using ChaCha20-Poly1305."""
    with open(encrypted_file, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(NONCE_SIZE)
        file_extension_length = int.from_bytes(f_in.read(1), 'big')
        file_extension = f_in.read(file_extension_length).decode('utf-8')
        tag = f_in.read(TAG_SIZE)
        ciphertext = f_in.read()

    key = derive_key(password, salt)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Incorrect password or tampered data")

    # Create the output file name by replacing the .xc extension with the original file extension
    output_file = os.path.splitext(encrypted_file)[0] + file_extension
    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)

    print(f'File decrypted to {output_file}')
