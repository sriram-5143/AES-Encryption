import argparse
from Crypto.Cipher import AES
from Crypto.Util import Counter

VERSION = "aes-ctr.py 0.2"

def main():
    cmd = argparse.ArgumentParser(
        prog="aes-ctr.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
        AES implementation in counter mode. This version supports 128 bits key encryption only.
        This is an experimental script. NO INPUT VALIDATION
        ''',
        epilog=
        

    cmd.add_argument("-d", "--decrypt", help="Use decrypt instead of default encrypt", action="store_true")
    cmd.add_argument("-i", "--input", help="File containing plaintext/ciphertext", type=str, required=True, metavar="IN")
    cmd.add_argument("-o", "--output", help="Output file to store result of the program", type=str, metavar="OUT")
    cmd.add_argument("-k", "--key", help="Encryption 128bits key", type=str, required=True)
    cmd.add_argument("-iv", help="Initial 128 bits counter", type=str, required=True)
    cmd.add_argument("-v", "--version", action="version", version=VERSION)
    args = cmd.parse_args()

    # Retrieve options and arguments 
    OUT_FILE = args.output if args.output else ''
    IN_FILE = args.input

    KEY = validate_hex(args.key)
    IV = validate_hex(args.iv)

    # Read file that contains plaintext / ciphertext 
    try:
        with open(IN_FILE, 'rb') as f:
            text = f.read()
    except FileNotFoundError:
        print(f"File {IN_FILE} not found.")
        sys.exit(1)

    # If key or init counter didn't pass validation test then abort 
    if KEY and IV:
        text_hex = text.hex()
        # Decryption 
        if args.decrypt:
            crypto(text_hex, KEY, IV, OUT_FILE, encrypt=False)
        # Encryption 
        else:
            crypto(text_hex, KEY, IV, OUT_FILE)
    else:
        print("Invalid Key or IV")

# Validate if passed value is hexadecimal and has proper length 
# Function returns passed argument if value is correct 
# If passed value is not valid, function returns False 
def validate_hex(hex_str):
    if len(hex_str) != 32:
        return False
    try:
        int(hex_str, 16)
        return hex_str
    except ValueError:
        return False

# Core function that performs encryption / decryption 
def crypto(text, key, iv, output, encrypt=True):
    BlockSizeForHex = 32
    encryption_key = bytes.fromhex(key)

    # Create new Counter object 
    counter = Counter.new(128, initial_value=int(iv, 16))

    # Create new AES CTR object 
    cipher = AES.new(encryption_key, AES.MODE_CTR, counter=counter)

    result = b''

    # Iterate over text 
    for i in range(0, len(text), BlockSizeForHex):
        # AES CTR operates on 16 bytes blocks 
        block = text[i:i+BlockSizeForHex]
        block_bytes = bytes.fromhex(block)
        if encrypt:
            result += cipher.encrypt(block_bytes)
        else:
            result += cipher.decrypt(block_bytes)

    if output:
        with open(output, 'wb') as f:
            f.write(result)
    else:
        print(result)

if __name__ == '__main__':
    main()

