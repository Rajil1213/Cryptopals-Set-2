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
prefix_length = rand().randint(1, 3 * AES.block_size) # can occupy at most three blocks (this is arbitrary)
PREFIX = Random.new().read(prefix_length)

def pad(msg):
    """prepends the `msg` with `your_string` and then, applies PKCS#7 padding

    Args:
        your_string (bytes): the byte-string to prepend to `msg`
        msg (bytes): a byte-string that is to be padded

    Returns:
        bytes: the padded byte-string
    """
    paddedMsg = msg

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
    """encrypts `your_string` + msg` + `UNKNOWN_STRING` using AES-ECB-128

    Args:
        your_string (bytes): byte-string used to prepend

    Returns:
        [bytes]: the byte-string of encrypted text
    """
    msg = bytes('The unknown string given to you was:\n', 'ascii')
    # append the `UNKNOWN_STRING` given to us to the `msg`, prepend `your_string` and then, the `PREFIX`
    plaintext = PREFIX + your_string + msg + b64decode(UNKNOWN_STRING)
    # Apply `PKCS#7` padding to correct size
    paddedPlaintext= pad(plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)

    return ciphertext


def detect_block_size():
    """detects the `block_size` used by the encryption_oracle()

    Returns:
        int: the `block_size` used by the encryption_oracle
    """
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        # on every iteration, add one more character
        feed  += feed
        # if the length of the ciphertext increases by more than 1,
        # PKCS#7 padding must have been added to make the size of plaintext == block_size
        # increase in the size gives the value of block_size
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)
        

def detect_mode(cipher):
    """detects whether the cipher-text was encrypted in ECB or not

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


def detect_prefix_length():
    """Detects the length of the prefix used in the oracle

    Returns:
        int: the length of the prefix
    """
    block_size = detect_block_size()

    # first find number of integer blocks occupied
    test_case_1 = encryption_oracle(b'a')
    test_case_2 = encryption_oracle(b'b')

    length1 = len(test_case_1)
    length2 = len(test_case_2)

    blocks = 0
    min_length = min(length1, length2)
    # if the any of the blocks (starting from the left) are the same,
    # these blocks are occupied by the `PREFIX`
    for i in range(0, min_length, block_size):
        if test_case_1[i:i+block_size] != test_case_2[i:i+block_size]:
            break
        blocks += 1

    # now calculate the residual number of bytes and add to total size 
    test_input = b''
    length = blocks * block_size
    # if adding an extra `?` does not change the current block of cipher-text
    # we've reached the end of that block, and so,
    # we've found the number of extra characters needed to complete the block with some prefix characters
    for extra in range(block_size):
        test_input += b'?'
        curr = encryption_oracle(test_input)[length: length+block_size]
        next = encryption_oracle(test_input + b'?')[length: length+block_size] 
        if curr == next:
            break
    
    residue = block_size - len(test_input)
    length += residue
    return length 


def ecb_decrypt(block_size):
    """decrypts the plaintext (without key) using byte-at-a-time attack (simple)

    Args:
        block_size (int): the `block_size` used by the `encryption_oracle()` for encryption
    """
    # common = lower_cases + upper_cases + space + numbers
    # to optimize brute-force approach
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'), ord('Z'))) + [ord(' ')] + list(range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)
    
    plaintext = b'' # holds the entire plaintext = sum of `found_block`'s
    check_length = block_size
    
    prefix_len = detect_prefix_length()
    print(f"Calculated Length of Prefix = { prefix_len }")
    check_begin = (prefix_len // block_size) * block_size
    residue = prefix_len % block_size

    while True:
        # as more characters in the block are found, the number of A's to prepend decreases
        prepend = b'A' * (block_size - 1 - (len(plaintext) + residue) % block_size)
        actual = encryption_oracle(prepend)[check_begin: check_begin+check_length]

        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[check_begin: check_begin+check_length]
            if actual == produced:
                plaintext += value
                found = True
                break
        
        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{ plaintext.decode('ascii') }")
            return
        
        if (len(plaintext) + residue) % block_size == 0: 
            check_length += block_size
    

def main():

    # detect block size
    block_size = detect_block_size()
    print(f"Block Size is { block_size }")

    # detect the mode (should be ECB)
    repeated_plaintext = b"A" * 50
    cipher = encryption_oracle(repeated_plaintext)
    mode = detect_mode(cipher)
    print(f"Mode of encryption is { mode }")

    # actual length of prefix
    print(f"Actual size of prefix = { len(PREFIX) }")

    # decrypt the plaintext inside `encryption_oracle()`
    ecb_decrypt(block_size)


if __name__ == "__main__":
    main()
