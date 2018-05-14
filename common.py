# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.

"""This module is designed for internal use by pyotp."""

from time import time as unix_time
from hmac import new as new_hmac, compare_digest

from pyotp.constants import HashAlgorithm, SecretEncoding


# These constants were taken from RFC 6238
_digits_mod = {
    0: 1,
    1: 10,
    2: 100,
    3: 1000,
    4: 10000,
    5: 100000,
    6: 1000000,
    7: 10000000,
    8: 100000000,
}


def get_code(secret, value, length, hash_algorithm):
    # Given the OTP secret, value, length, and hash algorithm, return the OTP
    # code
    code_length = _digits_mod[length]

    if not isinstance(value, bytes):
        value = value.to_bytes(8, "big")

    digest = new_hmac(secret, value, hash_algorithm.value)

    offset = digest[-1] & 0x0f

    code = int.from_bytes(digest[offset:offset+4], "big")
    code &= 0x7FFFFFFF
    code %= code_length

    return str(code).zfill(length)


def code_range(secret, length, hash_algorithm, start, end):
    # Return codes in a given range
    for ctr in range(start, end):
        # 64-bit integers only, please!
        ctr &= 0xFFFFFFFFFFFFFFFF
        yield get_code(secret, ctr, length, hash_algorithm)


def check_range(code, secret, hash_algorithm, start, end):
    # Check the code for validity in the given range between start and end
    # Non-constant time comparison
    # Assumes code length and generated lengths are equal
    length = len(code)
    for comp in code_range(secret, length, hash_algorithm, start, end):
        if code == comp:
            return True

    return False


def check_range_constant(code, secret, hash_algorithm, start, end):
    # Same as above, but constant-time-ish. No promises!
    length = len(code)

    for comp in code_range(secret, length, hash_algorithm, start, end):
        if compare_digest(code, comp):
            return True

    return False
