from Crypto.Cipher import AES
from random import Random

def random_key(length):
    """generates a random string `length` bytes in length

    Args:
        length (int): the length of the random string to generate

    Returns:
        str: a byte-string `length` bytes in length
    """
    key = b''
    choices = list(range(256))
    for i in range(length):
        choice = Random().choice(choices)
        hexVal = hex(choice).lstrip('0x')
        if len(hexVal) % 2 != 0:
            hexVal = '0' + hexVal
        key += bytes.fromhex(hexVal)

    if len(key) % length != 0:
        key += bytes(length - len(key) % length) # just in case the key is not `length` bytes in length (due to escape characters)
    return key


def pad(msg):
    """pads the `msg` byte-string with 5-10 random bytes on both ends, and then PKCS#7 padding

    Args:
        msg (bytes): a byte-string that is to be padded

    Returns:
        bytes: the padded byte-string
    """
    leftPadCnt = Random().randint(5, 10)
    rightPadCnt = Random().randint(5, 10)
    leftPad = random_key(leftPadCnt)
    rightPad = random_key(rightPadCnt)

    paddedMsg = leftPad + msg + rightPad 

    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg
    
    # PKCS#7 padding if the plain-text after padding isn't a multiple of AES.BLOCK_SIZE
    padding = size - (length % size)
    padValue = hex(padding).lstrip('0x')
    if len(padValue) == 1:
        padValue = '0' + padValue # bytes can't convert single digit hex
    padValue = bytes.fromhex(padValue)
    paddedMsg += padValue * padding

    return paddedMsg
    

def encryption_oracle(msg):
    """encrypts `msg` using AES in CBC/ECB alternatively with equal probability

    Args:
        msg (bytes): byte-string

    Returns:
        [bytes]: the byte-string of encrypted text
    """
    mode = Random().randint(0, 1)
    key = random_key(16)
    print(f"Key: { key }")
    paddedMsg = pad(msg)

    if mode:
        print("Chose ECB Mode")
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(paddedMsg)
    else:
        print("Chose CBC Mode")
        iv = random_key(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(paddedMsg)

    return ciphertext


def detect(cipher):
    """detects whether the cipher-text was encrypted in ECB or CBC mode

    Args:
        cipher (bytes): byte-string of cipher-text

    Returns:
        str: "EBC" | "CBC"
    """
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i+chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"

    return "CBC"


def main():
    msg = b"Yellow SubmarineTwo One Nine TwoYellow Submarine" * 2
    ciphertext = encryption_oracle(msg) 
    print(f"Detected: { detect(ciphertext) } mode")

if __name__ == "__main__":
    main()


