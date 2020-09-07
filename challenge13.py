from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import re

USER_DB = OrderedDict()
user_cnt = 0

class objectify:

    def __init__(self, cookie):
        self.cookie = cookie
        self.obj = OrderedDict()

    def convert(self):
        # if already converted
        if len(self.obj) > 0:
            return self.obj

        # get key=value pairs
        kv = self.cookie.split('&')
        # assign key=value pairs to dictionary: dict[key]=value
        for pair in kv:
            k, v = pair.split('=')
            self.obj[k] = v
        return self.obj

    def __repr__(self):
        self.convert()
        ret_value = "{\n"
        last_key = next(reversed(self.obj))
        for key, value in self.obj.items():
            if not key == last_key:
                ret_value += f"\t{ key }: '{ value }',\n"
            else:
                ret_value += f"\t{ key }: '{ value }'\n"
        ret_value += "}"
        return ret_value


def profile_for(user_info):
    # sanitize the `user_info` to remove '&' and '=' signs
    global user_cnt
    user_info = re.sub("&|=", "", user_info)
    cookie = f"email={ user_info }&uid={ user_cnt }&role=user"
    user_cnt += 1
    return cookie
    

def encrypt_profile(cookie):
    key = Random.new().read(16)
    paddedCookie = bytes(cookie, 'ascii')
    # Apply PKCS#7 padding if necessary
    if len(paddedCookie) % AES.block_size != 0:
        padLength = AES.block_size - len(paddedCookie) % AES.block_size
        padValue = bytes([padLength]) * padLength
        paddedCookie += padValue

    ecb = AES.new(key, AES.MODE_ECB)
    cipherCookie = ecb.encrypt(paddedCookie)
    return key, cipherCookie


def decrypt_profile(key, cipherCookie):
    ecb = AES.new(key, AES.MODE_ECB)
    plainCookie = ecb.decrypt(cipherCookie)
    # remove PKCS#7 padding
    if plainCookie[-1] in range(AES.block_size - 1):
        plainCookie = plainCookie[:-plainCookie[-1]]
    
    cookie = plainCookie.decode('ascii')
    # parse cookie to object format
    obj = objectify(cookie) 
    return cookie, str(obj)


def main():
    response = "y"
    while response.lower() == "y":
        user_info = input("Enter email id: ")
        cookie = profile_for(user_info)
        print(f"Plain cookie: { cookie }")
        key, cipherCookie = encrypt_profile(cookie)
        print(f"Encrypted cookie: { cipherCookie }")
        plainCookie, obj = decrypt_profile(key, cipherCookie)
        print(f"Decrypted cookie: { plainCookie }")
        print(f"Parsed cookie: \n{ obj }")
        response = input("Add more (y/n)? ")

if __name__ == "__main__":
    main()
