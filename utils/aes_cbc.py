if __name__ == "__main__":
    from aes import aes 
else:
    from utils.aes import aes


class cbc:

    BLOCK_SIZE = 16 # bytes    
    IV = bytes(16)  # 16-byte Initialization Vector
    key = b""
    AES = """the aes object to be initialized later"""

    def __init__(self, key):
        self.key = key
        self.AES = aes(self.key)


    def pad(self, text):
        """pads the `text` so that its size equals self.BLOCK_SIZE

        Args:
            text (bytes): the text to pad

        Returns:
            bytes: the padded text
        """

        length = len(text)
        padLength = length - (length % self.BLOCK_SIZE)
        padValue = hex(padLength).lstrip('0x')
        if len(padValue) == 1:
            padValue = '0' + padValue
        padding = padValue * padLength
        text += padding
        return text
    
    def xor(self, block1, block2):
        """performs XOR operation on two bytes of equal length

        Args:
            block1 (bytes): first block of bytes
            block2 (bytes): second block of bytes

        Returns:
            bytes: the result of `block1` XOR `block2`
        """

        hexBlock1 = block1.hex()
        hexBlock2 = block2.hex()

        deciBlock1 = int(hexBlock1, base=16)
        deciBlock2 = int(hexBlock2, base=16)

        result = deciBlock1 ^ deciBlock2
        result = hex(result).lstrip('0x')

        resultLength = len(result)
        requiredLength = 2 * self.BLOCK_SIZE

        if not resultLength == requiredLength:
            padLength = requiredLength - resultLength 
            result = '0' * padLength + result

        resultBlock = bytes.fromhex(result)
        return resultBlock


    def encrypt(self, plaintext):
        """perform encryption on `plaintext` using AES-128 in CBC mode

        Args:
            plaintext (bytes): the plaintext to encrypt

        Returns:
            bytes: the encrypted ciphertext
        """

        text = plaintext
        length = len(text)
        if length % self.BLOCK_SIZE != 0:
            text = self.pad(text)        

        addend = self.IV
        ciphertext = b""
        for i in range(0, length, self.BLOCK_SIZE):
            
            block = text[i:i+self.BLOCK_SIZE] 
            xord = self.xor(block, addend)
            encrypted = self.AES.encrypt(xord)
            addend = encrypted
            ciphertext += encrypted
        
        return ciphertext

    
    def decrypt(self, ciphertext):
        """decrypts the given `ciphertext`

        Args:
            ciphertext (bytes): the ciphertext to decrypt

        Returns:
            bytes: the plaintext after decryption
        """

        text = ciphertext
        length = len(text)

        addend = self.IV
        plaintext = b""
        for i in range(0, length, self.BLOCK_SIZE):

            block = ciphertext[i:i+self.BLOCK_SIZE]
            decrypted = self.AES.decrypt(block)
            xord = self.xor(addend, decrypted)
            plaintext += xord 
            addend = block

        return plaintext
    

if __name__ == "__main__":

    key = b'Thats my Kung Fu'
    plaintext = b'Two One Nine TwoNine Two Two One'

    cipher = cbc(key)

    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext}")
    print('='*40)
    recovered = cipher.decrypt(ciphertext)
    print(f"Recovered: {recovered}")
