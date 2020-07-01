from base64 import b64decode
import os
from utils.aes_cbc import cbc

def main():

    directory = 'files' 
    filename = '10.txt'
    path = os.path.join(directory, filename)

    with open(path, 'r') as f:
        lines = f.readlines()

    length = len(lines)
    for i in range(length):
        lines[i] = lines[i].rstrip()
    
    ciphertext = ''.join(lines)
    ciphertext = b64decode(ciphertext)

    key = b'YELLOW SUBMARINE'
    AES = cbc(key)
    
    plaintext = AES.decrypt(ciphertext)
    print(plaintext)

    print(plaintext.decode('ascii'))


if __name__ == "__main__":
    main()

