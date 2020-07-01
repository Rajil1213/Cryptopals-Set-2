from sys import exit

class aes:

    # encryption Substitution Box
    SBOX = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )
    
    # Decryption Substitution Box
    SBOX_INV = (
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            )
    
    # Diffusion Matrix for encryption to be used in Mix-Column Step
    DIFFUSION_MATRIX = (
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
            )

    # Inverse of Diffusion Matrix for decryption to be used in Inverse Mix Column Step
    DIFFUSION_MATRIX_INV = (
            0x0E, 0x0B, 0x0D, 0x09,
            0x09, 0x0E, 0x0B, 0x0D,
            0x0D, 0x09, 0x0E, 0x0B,
            0x0B, 0x0D, 0x09, 0x0E
            )

    # RoundKey Constants
    RC = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    roundKeys = []
    key = b""

    # Precomputation of Round Keys
    def g(self, byte, round):
        """Implements the g() function for randomization
        while generating round keys

        Args:
            byte (byte): the 32-bit value to perform the operation on
            round (int): the round-number

        Returns:
            string: the 32-bit output value
        """

        # shift
        # byte = 4 * 8 bits = 8 hex Values
        length = len(byte)
        noOfBytes = length // 2
        # print(length, end=' ')
        shiftedByte = []
        for i in range(0, noOfBytes):
            index = 2 * i
            asciiVal1 = byte[(index+2) % length]
            asciiVal2 = byte[(index+3) % length]
            asciiVal = asciiVal1 + asciiVal2
            shiftedByte.append(asciiVal)
        
        # print(f"Shifted: { shiftedByte }")

        # substitute
        for index in range(noOfBytes):

            i, j = shiftedByte[index]
            i = int(i, base=16)
            j = int(j, base=16)
            val = self.SBOX[i * 16 + j]
            shiftedByte[index] = val
        
        # print(f"Substituted Bytes: { shiftedByte }")
        
        # add round
        shiftedByte[0] ^= self.RC[round - 1]

        # print(f"After RC: { shiftedByte }")

        shiftedHexVal = list()        
        for shifted in shiftedByte:
            
            value = hex(shifted)[2:] # removes the '0x' from the beginning
            if len(value) == 1:
                value = '0' + value
            
            shiftedHexVal.append(value)

        # print(f"In hex: { shiftedHexVal }")
        
        shiftedHexVal = ''.join(shiftedHexVal)
        # print(f"g() => {shiftedHexVal}")
        
        return shiftedHexVal


    def generateRoundKeys(self):
        """generate the keys for each round of the encryption
        called during object instantiation
        """
        
        # initialize
        for i in range(0, 16, 4):
            keyByte = self.key[i:i+4]
            keyVal = keyByte.hex()  
            self.roundKeys.append(keyVal)
        
        # print(f"After Initialization: { self.roundKeys }")
        
        # recursive update
        for i in range(4, 44):

            numOfRound = (i // 4)
            if i % 4 == 0:
                term1 = self.roundKeys[i - 4]
                term2 = self.g(self.roundKeys[i - 1], numOfRound)
            else:
                term1 = self.roundKeys[i - 1]
                term2 = self.roundKeys[i - 4]

            # convert to decimal to perform XOR operation 
            term1Val = int(term1, base=16)
            term2Val = int(term2, base=16)
            result = term1Val ^ term2Val
            # convert back to hex and pad with necessary zeros
            hexVal = hex(result)[2:]
            if len(hexVal) != 8:
                padding = 8 - len(hexVal)
                hexVal = ('0' * padding) + hexVal
            self.roundKeys.append(hexVal)
            # print(f"Round: { numOfRound }")
            # print(self.roundKeys[i:i+4])


    def __init__(self, key):
        self.key = key
        self.generateRoundKeys()


    def getInitialState(self, text, decrypt=False):
        """converts the text into a 4X4 matrix column-wise, for further calculation

        Args:
            text (bytes): the input text
            decrypt (boolean, optional): set to True during decryption. Defaults to False.

        Returns:
            [list]: the text in matrix form as a list of lists
        """

        textBytes = text
        textHex = textBytes.hex()

        # initialize the 4x4 state matrix
        state = [[1 for i in range(4)] for j in range(4)]

        for j in range(4):
            for i in range(4):
                index = 2 * (j * 4 + i)
                hexVal = textHex[index:index+2]
                state[i][j] = hexVal

        return state

    # Key Addition Layer
    def addKey(self, productMatrix, round, decrypt=False):
        """adds the corresponding key for the `round` to the `productMatrix`

        Args:
            productMatrix (list): a list of lists representing the state matrix
            round (int): the round-number
            decrypt (bool, optional): set to True during decryption. Defaults to False.

        Returns:
            [list]: the state matrix formed through addition
        """
        
        rows = len(productMatrix)
        cols = len(productMatrix[0])

        sumMatrix = [[1 for i in range(4)] for j in range(4)]
        if decrypt:
            round = 10 - round

        # print(f"Using key for round: {round}")
        key = self.roundKeys[4*round: 4*round+4]
        key = ''.join(key)

        for j in range(cols):
            row = []
            for i in range(rows):
                index = 2 * (j * 4 + i)
                matVal = int(productMatrix[i][j], base=16)
                keyVal = int(key[index:index+2], base=16) # two nibbles at a time
                result = matVal ^ keyVal
                result = hex(result)[2:]
                if len(result) == 1:
                    result = '0' + result

                sumMatrix[i][j] = result
        
        return sumMatrix


    # Byte Substitution Layer
    def byteSub(self, addedMatrix, decrypt=False):
        """perfoms Byte Substitution on each  byte of `addedMatrix`
        using SBOX or SBOX_INV

        Args:
            addedMatrix (list): the input matrix
            decrypt (bool, optional): set to True during decryption. Defaults to False.

        Returns:
            list: the new state matrix as a result of byte substitution
        """

        stateMatrix = []
        rows = len(addedMatrix)
        cols = len(addedMatrix[0])

        if decrypt:
            SBOX = self.SBOX_INV
        else:
            SBOX = self.SBOX

        for i in range(rows):

            row = []
            for j in range(cols):

                byte = addedMatrix[i][j] 
                if len(byte) == 0:
                    byte = '0' + byte
                rowIndex = int(byte[0], base=16)
                colIndex = int(byte[1], base=16) 
                index = rowIndex * 16 + colIndex
                sbox = hex(SBOX[index])[2:]
                if len(sbox) == 1:
                    sbox = '0' + sbox
                row.append(sbox)

            stateMatrix.append(row)
        
        return stateMatrix 

    # diffusion layer
    def shiftRows(self, stateMatrix, decrypt=False):
        """shifts rows in `stateMatrix` left (encryption) or right (decryption)

        Args:
            stateMatrix (list): the input state matrix
            decrypt (bool, optional): set to True during decryption. Defaults to False.

        Returns:
            [list]: the new state matrix formed by shifting rows
        """

        shiftedMatrix = []

        rows = len(stateMatrix)
        cols = len(stateMatrix[0])

        for i in range(rows):
            row = []
            for j in range(cols):
                if decrypt:
                    colIndex = j - i # shift right
                else:
                    colIndex = (i + j) % rows # shift left
                value = stateMatrix[i][colIndex]
                row.append(value) 
            shiftedMatrix.append(row)
                
        return shiftedMatrix


    def gfMul(self, byte1, byte2):
        """Performs GF(2^8) multiplication on two bytes,
        using the Russian Peasant Method

        Args:
            byte1 (int): an 8-bit int
            byte2 (int): an 8-bit int

        Returns:
            int: an 8-bit int representing the product
        """
        p = 0
        msb = 0x80

        for i in range(8):
            # add at odd positions
            if byte2 & 1:
                p ^= byte1
            # check if the 8th bit is set, i.e., if there is carry
            carry = byte1 & msb
            # shift byte1 to analyze next byte
            byte1 = byte1 << 1
            # if carry, use mask for AES, the generator poly: x^8+x^4+x^3+x+1
            if carry:
                byte1 ^= 0x11b
            byte2 = byte2 >> 1
        
        return p


    def mixColumns(self, shiftedMatrix, decrypt=False):
        """performs mix column operation on the given `shiftedMatrix`

        Args:
            shiftedMatrix (list): the input matrix
            decrypt (bool, optional): set to True during decryption. Defaults to False.

        Returns:
            list: the matrix representing the result of the Mix Column Operation
        """

        rows = len(shiftedMatrix)
        diffRows = 4
        cols = len(shiftedMatrix[0])

        productMatrix = [[i for i in range(4)] for j in range(4)]

        if decrypt:
            diffMat = self.DIFFUSION_MATRIX_INV
        else:
            diffMat = self.DIFFUSION_MATRIX

        for i in range(cols):
            for j in range(diffRows):
                total = 0
                for k in range(rows):
                    diffElem = diffMat[j * 4 + k]
                    shiftMatElem = int(shiftedMatrix[k][i], base=16)
                    product = self.gfMul(diffElem, shiftMatElem) 
                    total ^= product
                
                hexVal = hex(total)[2:]
                if len(hexVal) == 1:
                    hexVal = '0' + hexVal
                productMatrix[j][i] = hexVal

        return productMatrix

    
    def getText(self, state):
        """gets the text in bytes from the given `state` matrix

        Args:
            state (list): list of lists representing the state matrix

        Returns:
            bytes: the text in the form of bytes
        """

        rows = len(state)
        cols = len(state[0])

        hexVal = ""

        for j in range(cols):
            for i in range(rows):
                value = state[i][j]
                hexVal += value
        
        # print(hexVal)
        text = bytes.fromhex(hexVal)
        return text
    
    def encrypt(self, plaintext):
        """perform encryption on the given plaintext

        Args:
            plaintext (bytes): the plaintext in bytes, must be 128 bytes in length

        Returns:
            bytes: the encrypted string
        """

        # initial block
        state = self.getInitialState(plaintext)
        # print(f"Initial State: {state}")
        added = self.addKey(state, 0)
        # print(f"After Key 0 Add: {added}")
 
        # 9 rounds of full block
        for numRound in range(1, 10):
            # print(f"Round {numRound}")
            subbed = self.byteSub(added)
            # print(f"Byte Substitution: {subbed}")
            shifted = self.shiftRows(subbed)
            # print(f"Row Shifted: {shifted}")
            mixed = self.mixColumns(shifted)
            # print(f"Mix Columned: {mixed}")
            added = self.addKey(mixed, numRound)
            # print(f"Add Key'd: {added}")

        # final block
        # print("Final Round:")
        subbed = self.byteSub(added)
        # print(f"Byte Subbed: {subbed}")
        shifted = self.shiftRows(subbed)
        # print(f"Row Shifted: {shifted}")
        state = self.addKey(shifted, 10)
        # print(f"Add Key'd: {state}")

        ciphertext = self.getText(state)
        
        return ciphertext

    def decrypt(self, ciphertext):
        """performs decryption on the given `ciphertext`

        Args:
            ciphertext (bytes): the ciphertext in bytes

        Returns:
            byte: the recovered plaintext in bytes
        """

        decrypt = True
        # initial block
        state = self.getInitialState(ciphertext, decrypt=decrypt)
        # print(f"Initial State: {state}")
        added = self.addKey(state, 0, decrypt=decrypt)
        # print(f"After Key 10 Add: {added}")
        shifted = self.shiftRows(added, decrypt=decrypt)
        # print(f"Row Shifted: {shifted}")
        subbed = self.byteSub(shifted, decrypt=decrypt)
        # print(f"Bytes Subbed: {subbed}")

        # 9 rounds of full block
        for numRound in range(1, 10):

            # print(f"Round {numRound}")
            added = self.addKey(subbed, numRound, decrypt=decrypt)
            # print(f"Add Key'd: {added}")
            mixed = self.mixColumns(added, decrypt=decrypt)
            # print(f"Mix Columned: {mixed}")
            shifted = self.shiftRows(mixed, decrypt=decrypt)
            # print(f"Row Shifted: {shifted}")
            subbed = self.byteSub(shifted, decrypt=decrypt)
            # print(f"Byte Substitution: {subbed}")

        # final block
        # print("Final Round:")
        state = self.addKey(subbed, 10, decrypt=decrypt)
        # print(f"Add Key'd: {state}")

        plaintext = self.getText(state)
        
        return plaintext



def testSuite():

    encrypt = aes(b'Thats my Kung Fu')
    
    # print("Key Generation Test")
    keys = encrypt.roundKeys

    # print(f"Generated {len(keys)} roundKeys") # 44
    """
    for i in range(0, 44, 4):
        print(f"Round {i}")
        print(keys[i], end=',')
        print(keys[i+1], end=',')
        print(keys[i+2], end=',')
        print(keys[i+3])
    """
    # print("Initial State Matrix Test")
    state = encrypt.getInitialState(b"Two One Nine Two")
    # print(state)
    """
    [['54', '4f', '4e', '20'],
     ['77', '6e', '69', '54'],
     ['6f', '65', '6e', '77'],
     ['20', '20', '65', '6f']]
    """

    # print("Add Round Key Test for Round 0")    
    added = encrypt.addKey(state, 0)
    # print(added)
    """
    [['00', '3c', '6e', '47'],
     ['1f', '4e', '22', '74'],
     ['0e', '08', '1b', '31'],
     ['54', '59', '0b', '1a']]
    """

    # print("Byte Substitution Test Round 1")
    subs = encrypt.byteSub(added)
    # print(subs)
    """
    [['63', 'eb', '9f', 'a0'],
     ['c0', '2f', '93', '92'],
     ['ab', '30', 'af', 'c7'],
     ['20', 'cb', '2b', 'a2']]  
    """
    # print("Shift Rows Test")
    shifted = encrypt.shiftRows(subs)
    # print(shifted)
    """
    [['63', 'eb', '9f', 'a0'], 
     ['2f', '93', '92', 'c0'], 
     ['af', 'c7', 'ab', '30'], 
     ['a2', '20', 'cb', '2b']]
    """

    # print("Mix Columns Test")
    mixed = encrypt.mixColumns(shifted)
    # print(mixed)
    """
    [['ba', '84', 'e8', '1b'], 
     ['75', 'a4', '8d', '40'],
     ['f4', '8d', '6', '7d'], 
     ['7a', '32', 'e', '5d']]
    """

    # print("Add Round Key Test for Round 1")
    added = encrypt.addKey(mixed, 1)
    # print(added)
    """
    [['58', '15', '59', 'cd'], 
     ['47', 'b6', 'd4', '39'], 
     ['08', '1c', 'e2', 'df'], 
     ['8b', 'ba', 'e8', 'ce']]
    """
    # print("Byte Substitution Test for Round 2")
    subbed = encrypt.byteSub(added) 
    # print(subbed)
    """
    [['6a', '59', 'cb', 'bd'], 
     ['a0', '4e', '48', '12'], 
     ['30', '9c', '98', '9e'], 
     ['3d', 'f4', '9b', '8b']]
    """

    plaintext = b"Two One Nine Two"
    ciphertext = encrypt.encrypt(plaintext)
    print(ciphertext)
    """
    29c3505f571420f6402299b31a02d73a
    b')\xc3P_W\x14 \xf6@"\x99\xb3\x1a\x02\xd7:'
    """
    plaintext = encrypt.decrypt(ciphertext)
    print(plaintext) 


if __name__ == "__main__":

    testSuite()    
