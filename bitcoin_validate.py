# bitcoin_validate.py

# standalone utility

import pytest
import binascii
import hashlib
import base58

# <BEGIN bech32m.py> ###################################################
# Copyright (c) 2017, 2020 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32/Bech32m and segwit addresses."""

from enum import Enum

class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""

    BECH32 = 1
    BECH32M = 2

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None

def bech32_create_checksum(hrp, data, spec):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

def bech32_decode(bech):
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (
        data[0] == 0
        and spec != Encoding.BECH32
        or data[0] != 0
        and spec != Encoding.BECH32M
    ):
        return (None, None)
    return (data[0], decoded)

def encode(hrp, witver, witprog):
    """Encode a segwit address."""
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)
    if decode(hrp, ret) == (None, None):
        return None
    return ret

# <END bech32m.py> #####################################################

# <BEGIN default_validator.py> #########################################

def _base58_decode(address: str) -> bool:
    """
    SEE https://en.bitcoin.it/wiki/Base58Check_encoding
    """
    try:
        decoded_address = base58.b58decode(address).hex()
        result, checksum = decoded_address[:-8], decoded_address[-8:]

    except ValueError:
        return False

    else:
        for _ in range(1, 3):
            result = hashlib.sha256(binascii.unhexlify(result)).hexdigest()

        return checksum == result[:8]

def _bech32_decode(address: str) -> bool:
    """
    SEE https://github.com/bitcoin/bips/blob/1f0b563738199ca60d32b4ba779797fc97d040fe/bip-0350.mediawiki
    """
    decoded_address = bech32_decode(address)

    if None in decoded_address:
        return False

    return True

def is_valid_address(address: str) -> bool:
    """
    Validates the passed btc address.
    Args:
        address (str): Currency address to validate.

    Returns:
        bool: Result of address validation.
    """
    return _base58_decode(address) or _bech32_decode(address)

# <END default_validator.py> ###########################################

# <BEGIN tests> ########################################################

def test_base58_decode():
    address = 'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg40'
    d = _base58_decode(address)
    print(f"_base58_decode {address} -> {d}")
    address = '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT1'
    d = _base58_decode(address)
    print(f"_base58_decode {address} -> {d}")

def test_bech32_decode():
    address = '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT1'
    d = _bech32_decode(address)
    print(f"_bech32_decode {address} -> {d}")
    address = 'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg40'
    d = _bech32_decode(address)
    print(f"_bech32_decode {address} -> {d}")

def test_address_is_valid():
    addresses = [
        '15e15hWo6CShMgbAfo8c2Ykj4C6BLq6Not',
        '35PBEaofpUeH8VnnNSorM1QZsadrZoQp4N',
        'bc1q42lja79elem0anu8q8s3h2n687re9jax556pcc',
        '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT1',
        '1GRKR41WzKpcrD5RpUeMQ1NK6JG46sAtFh',
        'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg40',
        'bc1q7w9p2unf3hngtzmq3sq47cjdd0xd9sw7us5h6p',
        'bc1p7qxqlecjcqej0564745xl42lmm7kddgqp5llhjd3w32n4vxmnduqj9n6hp',
        'bc1plyq2dmxqtmwnvmfpk47pygp6426vjj2sj5e9n54x96ge967rrpgq27jc2v',
        'bc1p3nhp6eawl9a9lxaydlkl9ewhumatgt9v9trcnuutexda86gz3lwqsw3yxf',
        'bc1psx9ukcl7ft7aadjsma6k6xld8yhgkhjv72qs246hstc4ayzhxwwq3ju86w',
        'bc1plyq2dmxqtmwnvmfpk47pygp6426vjj2sj5e9n54x96ge967rrpgq27jc2v'
    ]
    for i in addresses:
        print(f"is_valid_address {i} -> {is_valid_address(i)}")

def test_address_is_invalid():
    addresses = [
        '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT',
        '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT11',
        '21hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT11',
        '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT2',
        'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg4',
        'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg401',
        'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg41',
        'bc1q7w9p2unf3hngtzmq3sq47cjdd0xd9sw7us5h6p1',
        'bc1psx9ukcl7ft7aadjsma6k6xld8yhgkhjv72qs246hstc4ayzhxwwq3ju86',
        'bc1plyq2dmxqtmwnvmfpk47pygp6426vjj2sj5e9n54x96ge967rrpgq27jc2vc'
        'bc1psx9ukcl7ft7aadjsma6k6xld8yhgkhjv72qs246hstc4ayzhxwwq3ju86q',
        'bc1plyq2dmxqtmwnvmfpk47pygp6426vjj2sj5e9n54x96ge967rrpgq27jc2z'
        'cosmos16na5gpcj80tafv5gycm4gk7garj8jjsgydtkmq',
        '12345',
        'qwerty',
        '',
        '31hr5x7HpgUTNJsdukGEUmjNNTiyVr9aT',
        'bc1qnpgqxy7nq7zt6snx0kn76lv3z6xz5dtceupg401',
        'мой биткоин адрес',
        '比特币地址',
        'Àåæ´ýú.ü.£ßòÒÀì£Ê·¸®±ô¿¯åÇÊ¯¯ï',
        '-[:%/~%`!,)+~;{.\\-.%.**_[(\\$".'
    ]
    for i in addresses:
        print(f"is_valid_address {i} -> {is_valid_address(i)}")

def run_tests():
    test_base58_decode()
    test_bech32_decode()    
    test_address_is_valid()
    test_address_is_invalid()

# <END tests> ##########################################################

if __name__ == '__main__':
    
    print("Running tests...")
    print("#"*80)
    run_tests()
    print("#"*80)
    print("Testing complete.")
    
