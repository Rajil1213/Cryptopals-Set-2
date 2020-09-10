from Crypto.Cipher import AES
from Crypto import Random
import re


def pad(value, size):
    """applies PKCS#7 padding to `value` to make it of size `size`

    Args:
        value (bytes): a byte-string to pad
        size (size): the required size

    Returns:
        bytes: a byte-string = `value` + padding, such that its size is `size`
    """
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue


class InvalidPaddingError(Exception):

    def __init__(self, paddedMsg, message="has invalid PKCS#7 padding."):
        self.paddedMsg = paddedMsg
        self.message = message
        super().__init__(self.message)
    
    def __repr__(self):
        return f"{ self.paddedMsg } { self.message }"


def valid_padding(paddedMsg, block_size):
    """checks if `paddedMsg` has valid PKCS#7 padding for given `block_size`

    Args:
        paddedMsg (bytes): the padded text
        block_size (int): the block size that is to be obtained by padding

    Returns:
        bool: True, if the padding is valid. False, otherwise. 
    """
    # if the length of the `paddedMsg` is not a multiple of `block_size`
    if len(paddedMsg) % block_size != 0:
        return False
    
    last_byte = paddedMsg[-1] 

    # if the value of the last_byte is greater than or equal to block_size
    if last_byte >= block_size:
        return False
    
    padValue = bytes([last_byte]) * last_byte
    # if all the padding bytes are not the same
    if paddedMsg[-last_byte:] != padValue:
        return False
    
    # if, after removing the padding, the remaining characters are not all printable
    if not paddedMsg[:-last_byte].decode('ascii').isprintable():
        return False
    
    return True


def remove_padding(paddedMsg, block_size):
    """removes padding from `paddedMsg`, displays error-message if padding is invalid

    Args:
        paddedMsg (bytes): the message that is padded using PKCS#7 padding
        block_size (int): the block size that is obtained by said padding

    Raises:
        InvalidPaddingError: if the padding is invalid
    
    Returns: 
        (byte): the message after removal of padding, if valid.
    """ 
    if not valid_padding(paddedMsg, block_size):
        raise InvalidPaddingError
    
    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    return unpadded


QUOTE = {b';':b'%3B', b'=':b'%3D'}
UNQUOTE = {v:k for k, v in QUOTE.items()}

KEY = Random.new().read(AES.block_size)
IV = bytes(AES.block_size) # for simplicity just a bunch of 0's

def cbc_encrypt(input_text):

    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    for key in QUOTE:
        input_text = re.sub(key, QUOTE[key], input_text)
    
    plaintext = prepend + input_text + append
    plaintext = pad(plaintext, AES.block_size)
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def check(ciphertext):

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Plaintext: { plaintext }")

    if b";admin=true;" in plaintext:
        return True
    
    return False


def test():

    input_string = b";admin=true;"
    ciphertext = cbc_encrypt(input_string)
    if check(ciphertext):
        print("Admin Found")
    else:
        print("Admin Not Found")


if __name__ == "__main__":
    test()

