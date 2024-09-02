import argparse
import sys
from Crypto.Cipher import AES
from Crypto.Util import Counter

VERSION = "aes-ctr.py 0.2"

def main():
    cmd = argparse.ArgumentParser(
        prog="aes-ctr.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
        AES implementation in counter mode. This version supports 128-bit key encryption only.
        This is an experimental script. INPUT VALIDATION HAS BEEN IMPLEMENTED.
        ''',
        epilog="Example usage:\npython aes-ctr.py -i plaintext.txt -o encrypted.txt -k 0123456789abcdef0123456789abcdef -iv 0123456789abcdef0123456789abcdef"
    )
    
    cmd.add_argument("-d", "--decrypt", help="Use decrypt instead of default encrypt", action="store_true")
    cmd.add_argument("-i", "--input", help="File containing plaintext/ciphertext", type=str, required=True, metavar="IN")
    cmd.add_argument("-o", "--output", help="Output file to store result of the program", type=str, metavar="OUT")
    cmd.add_argument("-k", "--key", help="Encryption 128-bit key (hexadecimal)", type=str, required=True)
    cmd.add_argument("-iv", help="Initial 128-bit counter (hexadecimal)", type=str, required=True)
    cmd.add_argument("-v", "--version", action="version", version=VERSION)
    args = cmd.parse_args()

    # Validate Key and IV
    KEY = validate_hex(args.key, 32)
    IV = validate_hex(args.iv, 32)

    if not KEY or not IV:
        print("Invalid Key or IV. Both must be 32-character long hexadecimal strings.")
        sys.exit(1)

    # Read the input file containing plaintext/ciphertext
    try:
        with open(args.input, 'rb') as f:
            text = f.read()
    except FileNotFoundError:
        print(f"File {args.input} not found.")
        sys.exit(1)

    # Perform encryption or decryption
    crypto(text, KEY, IV, args.output, encrypt=not args.decrypt)

# Validate if passed value is a valid hexadecimal string and has the correct length
def validate_hex(hex_str, length):
    if len(hex_str) != length:
        return False
    try:
        int(hex_str, 16)
        return hex_str
    except ValueError:
        return False

# Core function that performs encryption/decryption
def crypto(text, key, iv, output=None, encrypt=True):
    encryption_key = bytes.fromhex(key)

    # Create a new Counter object
    counter = Counter.new(128, initial_value=int(iv, 16))

    # Create a new AES CTR object
    cipher = AES.new(encryption_key, AES.MODE_CTR, counter=counter)

    if encrypt:
        result = cipher.encrypt(text)
    else:
        result = cipher.decrypt(text)

    if output:
        with open(output, 'wb') as f:
            f.write(result)
    else:
        print(result.hex())

if __name__ == '__main__':
    main()
