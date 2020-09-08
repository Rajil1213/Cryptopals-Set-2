from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import re

USER_DB = OrderedDict()
user_cnt = 0
KEY = Random.new().read(16)

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


def get_cookie(user_info):
    # sanitize the `user_info` to remove '&' and '=' signs
    global user_cnt
    user_info = re.sub("&|=", "", user_info)
    cookie = f"email={ user_info }&uid={ user_cnt }&role=user"
    user_cnt += 1
    return cookie


def pad(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue
    

def encrypt_profile(cookie):
    paddedCookie = bytes(cookie, 'ascii')
    # Apply PKCS#7 padding if necessary
    paddedCookie = pad(paddedCookie, AES.block_size)
    ecb = AES.new(KEY, AES.MODE_ECB)
    cipherCookie = ecb.encrypt(paddedCookie)
    return cipherCookie


def profile_for(user_info):
    cookie = get_cookie(user_info)
    return encrypt_profile(cookie)


def decrypt_profile(key, cipherCookie):
    ecb = AES.new(key, AES.MODE_ECB)
    plainCookie = ecb.decrypt(cipherCookie)
    # remove PKCS#7 padding
    last_byte = plainCookie[-1]
    if last_byte in range(AES.block_size - 1):
        padding = bytes([last_byte]) * last_byte
        if plainCookie[-last_byte:] == padding:
            plainCookie = plainCookie[:-plainCookie[-1]]
    
    cookie = plainCookie.decode('ascii')
    # parse cookie to object format
    obj = objectify(cookie) 
    return cookie, str(obj)


def create_admin_profile():
    # first create a block so that `email=<x>&uid=<x>&role=` occupies one block_size
    # and value of the role occupies the last block
    cookie_parts = 'email=@gmail.com&uid=2&role='
    username = 'A' * (AES.block_size - len(cookie_parts) % AES.block_size)
    email = username + "@gmail.com"
    cipherCookie1 = profile_for(email)

    # second, create a block so that `admin` occupies a block for itself
    # create an email that occupies one full block
    cookie_param = "email="
    hacker_mail = 'A' * (AES.block_size - len(cookie_param) % AES.block_size)
    # now append 'admin' + 'padding' to the mail so that it occupies a block of its own
    value = pad(b'admin', AES.block_size).decode('ascii')
    hacker_mail += value
    cipherCookie2 = profile_for(hacker_mail)

    # all except the last block of `cipherCookie1` i.e., `email=***@gmail.com&uid=0&role=`
    block1 = cipherCookie1[:-AES.block_size]
    # just the block containing `admin`, here it is the second block 
    block2 = cipherCookie2[AES.block_size:AES.block_size*2]
    # concatenate `block1` and `block2`
    cipherBlock = block1 + block2 

    cookie, obj = decrypt_profile(KEY, cipherBlock)
    print(f"Cookie Created: { cookie }")
    print(f"Object Created: { obj }")


def main():
    response = "y"
    """
    # test individual functions
    while response.lower() == "y":
        user_info = input("Enter email id: ")
        cookie = get_cookie(user_info)
        print(f"Plain cookie: { cookie }")
        cipherCookie = encrypt_profile(cookie)
        print(f"Encrypted cookie: { cipherCookie }")
        plainCookie, obj = decrypt_profile(KEY, cipherCookie)
        print(f"Decrypted cookie: { plainCookie }")
        print(f"Parsed cookie: \n{ obj }")
        response = input("Add more (y/n)? ")
    """ 
    create_admin_profile()

if __name__ == "__main__":
    main()
