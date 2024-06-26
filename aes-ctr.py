# AES cryptography algorithm implementation in Counter mode



from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys, argparse

VERSION = "aes-ctr.py 0.1"

def main():
    cmd = argparse.ArgumentParser(
	    prog="aes-ctr.py",
	    formatter_class=argparse.RawDescriptionHelpFormatter,
	    description = '''
	    \rAES implementation in counter mode. This version supports 128 bits key encryption only.
	    \rThis is experimental script. NO INPUT VALIDATION
	    ''',
	    epilog = '''
	    \rExemplary usage:\n
	    \r1) Encryption
	    \r$ python aes-ctr.py -i plaintext -o ciphertext -k abcdef1234567890abcdef1234567890 -iv 01010101010101010101010101010101\n
	    \r2) Decryption
	    \r$ aes-ctr.py -d -i ciphertext -o plaintext -k abcdef1234567890abcdef1234567890 -iv 01010101010101010101010101010101
	    ''')

    cmd.add_argument("-d", "--decrypt", help="Use decrypt instead of default encrypt", action="store_true")
    cmd.add_argument("-i", "--input", help="File containing plaintext/ciphertext", type=str, required=True, metavar="IN")
    cmd.add_argument("-o", "--output", help="Output file to store result of the program", type=str, metavar="OUT")
    cmd.add_argument("-k", "--key", help="Encryption 128bits key", type=str, required=True)
    cmd.add_argument("-iv", help="Initial 128 bits counter", type=str, required=True)
    cmd.add_argument("-v", "--version", action="version", version=VERSION)
    args = cmd.parse_args()

    # Retrieve options and arguments # 
    if args.output:
	OUT_FILE = args.output
    else:
	OUT_FILE = ''

    IN_FILE = args.input

    KEY = validateHex(args.key)
    IV = validateHex(args.iv)

    # Read file that contains plaintext / ciphertext #  
    f = open(IN_FILE, 'rb')
    text = f.read()
    f.close()

    # If key or init counter didn't pass validation test then abort #
    if KEY and IV:
	# Decryption #
	if args.decrypt:
	    crypto(text.encode("hex"), KEY, IV, OUT_FILE, encrypt=False)
	# Encryption #
	else:
	    crypto(text.encode("hex"), KEY, IV, OUT_FILE)
    else:
	print "Invalid Key or iv"

# Validate if passed value is hexadecimal and has proper length #
# Function returns passed argument if value is correct #
# If passed value is not valid, function returns False #
def validateHex(hex):
    if len(hex) is not 32:
	return False
    else:
	try:
	    int(hex,16)
	    return hex
	except ValueError:
	    return False

# Core function that performs encryption / decryption #
def crypto(text, key, iv, output, encrypt=True):

    BlockSizeForHex = 32;
    encryptionKey = key.decode("hex")

    # Create new Counter object #
    # Object will automatically increment counter on each cryptographic round #
    counter = Counter.new(128, initial_value=int(iv,16))

    # Create new AES CTR object #
    cipher=AES.new(encryptionKey, AES.MODE_CTR, counter=counter)

    result = ''

    # Iterate over text #
    for i in range(0,len(text),BlockSizeForHex):

	# AES CTR operates on 16 bytes blocks #
	block = text[i:i+BlockSizeForHex]
	if encrypt:
	    result += cipher.encrypt(block.decode("hex"))
	else:
	    result += cipher.decrypt(block.decode("hex"))

    if output:
	f = open(output,'wb')
	f.write(result)
	f.close()
    else:
	print result


if __name__ == '__main__':
    main()
