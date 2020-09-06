from base64 import b64decode
from Crypto import Random 
from Crypto.Cipher import AES
from random import Random as rand

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
# b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n" 

KEY = Random.new().read(16)

def pad(your_string, msg):
    """pads the `msg` byte-string with 5-10 random bytes on both ends, and then PKCS#7 padding

    Args:
        msg (bytes): a byte-string that is to be padded

    Returns:
        bytes: the padded byte-string
    """
    paddedMsg = your_string + msg

    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg
    
    # PKCS#7 padding if the plain-text after padding isn't a multiple of AES.BLOCK_SIZE
    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding

    return paddedMsg
    

def encryption_oracle(your_string):
    """encrypts `msg` using AES in CBC/ECB alternatively with equal probability

    Args:
        msg (bytes): byte-string

    Returns:
        [bytes]: the byte-string of encrypted text
    """
    msg = b'The unknown string given to you was: ' + b64decode(UNKNOWN_STRING)
    paddedMsg = pad(your_string, msg)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedMsg)

    return ciphertext


def detect_block_size():
    feed = b"A"
    length = 0
    cnt = 0
    while True:
        cipher = encryption_oracle(feed)
        feed  += feed
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)
        

def detect_mode(cipher):
    """detects whether the cipher-text was encrypted in ECB or CBC mode

    Args:
        cipher (bytes): byte-string of cipher-text

    Returns:
        str: "ECB" | "not ECB"
    """
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i+chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"

    return "not ECB"


def ecb_decrypt(block_size):
    # common = lower_cases + upper_cases + space + numbers
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'), ord('Z'))) + [ord(' ')] + list(range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)
    found_block = b''
    plaintext = b''
    check_length = block_size
    while True:
        append = b'A' * (15 - len(found_block))
        actual = encryption_oracle(append)
        if check_length > len(actual):
            print(f"Plaintext: { plaintext }")
            return
        actual = actual[:check_length]
        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = append + plaintext + found_block + value
            produced = encryption_oracle(your_string)[:check_length]
            if actual == produced:
                # print(f"your-string = { your_string }")
                found_block += value
                # print(found)
                found = True
                break
        
        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: { plaintext + found_block }")
            return
        
        if len(found_block) == block_size:
            # print(f"Block { check_length // block_size }: { found_block }")
            plaintext += found_block
            check_length += block_size
            found_block = b''
    

def main():
    """
    # detect block size
    block_size = detect_block_size()
    print(f"Block Size is { block_size }")

    # detect the mode (should be ECB)
    dumb_plaintext = b"A" * 50
    dumb_cipher = encryption_oracle(b'', dumb_plaintext)
    mode = detect_mode(dumb_cipher)
    print(f"Mode of encryption is { mode }")
    """
    block_size = 16 
    ecb_decrypt(block_size)



if __name__ == "__main__":
    main()
