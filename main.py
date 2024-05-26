import argparse
import secrets
from crypto_utils import aes256, otp, ChaCha20
def generate_password(length=32):
    """Generate a secure password using the secrets library."""
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(secrets.choice(characters) for _ in range(length))

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt files.')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='action to perform')
    parser.add_argument('-f', '--file', required=True, help='file to process')
    parser.add_argument('-p', '--password', help='password to use for encryption/decryption')
    parser.add_argument('-a', '--algorithm', choices=['aes256', 'otp', 'chacha'], default='aes256', help='algorithm to use for encryption/decryption')

    args = parser.parse_args()

    if args.action == 'encrypt':
        if args.algorithm == 'aes256':
            if not args.password:
                args.password = generate_password()
                print(f"No password provided. Generated password: {args.password}")
            aes256.encrypt_file(args.file, args.password)
        elif args.algorithm == 'chacha':
            if not args.password:
                args.password = generate_password()
                print(f"No password provided. Generated password: {args.password}")
            ChaCha20.encrypt_file(args.file, args.password)
        elif args.algorithm == 'otp':
            print("otp")
            otp.xor_encrypt(args.file)

    elif args.action == 'decrypt':
        if args.algorithm == 'aes256':
            if not args.password:
                print("Error: Password is required for decryption.")
                return
            aes256.decrypt_file(args.file, args.password)
        elif args.algorithm == 'chacha':
            if not args.password:
                print("Error: Password is required for decryption.")
                return
            ChaCha20.decrypt_file(args.file, args.password)
        elif args.algorithm == 'otp':
            print("otp")
            if not args.password:
                print("Error: Keyfile is required for decryption(-p <filepath>).")
                return
            otp.xor_decrypt(args.file, args.password)

if __name__ == '__main__':
    main()
