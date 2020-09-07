from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import re

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


def main():
    cookie = "name=admin&role=admin&id=0"
    obj = objectify(cookie)
    print(obj)


if __name__ == "__main__":
    main()
