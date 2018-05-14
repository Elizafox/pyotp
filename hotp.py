# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.


"""HOTP-related functions."""


from pyotp.constants import HashAlgorithm
from pyotp.common import get_code, check_range, check_range_constant


def get_hotp_code(secret, counter, length=6, hash_algorithm=HashAlgorithm.SHA1):
    """Get an HOTP code of the given length using the given secret.

    It is not recommended to use any algorithm but SHA1 unless you know what
    you are doing, due to interoperability concerns.
    """
    return get_code(secret, counter, length, hash_algorithm)


def check_hotp(code, secret, counter, hash_algorithm=HashAlgorithm.SHA1,
               below=0, above=15, constant_time=True):
    """Check if the given HOTP code matches the given counter.

    It is not recommended to use any algorithm but SHA1 unless you know what
    you are doing, due to interoperability concerns.

    below and above specify values less than and greater than counter to check,
    respectively. For example, given counter 200, with above and below at 10,
    it will check 190 and 210 as well. This is in case they incremented the
    counter by mistake.

    constant_time determines if a constant time string comparison is used, to
    help mitigate timing attacks.
    """
    start = counter - below
    end = counter + above
    if constant_time:
        return check_range_constant(code, secret, hash_algorithm, start, end)
    else:
        return check_range(code, secret, hash_algorithm, start, end)
