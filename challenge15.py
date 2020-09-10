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
        ValueError: if the padding is invalid and then, shows an error message
    """ 
    try:
        if not valid_padding(paddedMsg, block_size):
            raise ValueError
    except ValueError:
        print(f"{ paddedMsg } has invalid PKCS#7 padding.")
        return
    
    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    print(f"Padding removed successfully...")
    print(f"Before padding removal: { paddedMsg }")
    print(f"After padding removal: { unpadded }")


def test():
    """tests the `remove_padding()` function for various test cases.
    """

    block_size = 16

    # Test case 1: incorrect value < required:
    paddedMsg = b'ICE ICE BABY\x03\x03\x03\x03'
    remove_padding(paddedMsg, block_size)

    # Test caes 2: incorrect value > required:
    paddedMsg = b"ICE ICE BABY\x05\x05\x05\x05" 
    remove_padding(paddedMsg, block_size)

    # Test case 3: incorrect length:
    paddedMsg = b"ICE ICE BABY\x04\x04\x04"
    remove_padding(paddedMsg, block_size)

    # Test case 4: variable numbers:
    paddedMsg = b"ICE ICE BABY\x01\x02\x03\x04"
    remove_padding(paddedMsg, block_size)

    # Test case 5: correct padding 
    paddedMsg = b"ICE ICE BABY\x04\x04\x04\x04"
    remove_padding(paddedMsg, block_size)


if __name__ == "__main__":
    test()
