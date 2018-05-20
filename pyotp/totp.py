# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.


"""TOTP-related functions."""


from time import time

from pyotp.constants import HashAlgorithm
from pyotp.common import get_code, check_range, check_range_constant


def get_totp_code(secret, timestamp=None, length=6, grace_period=30,
                  hash_algorithm=HashAlgorithm.SHA1):
    """Get TOTP code of the given length using the given secret.

    If timestamp is None, the current system time will be used. Beware though:
    it is important to have accurate system time.

    The grace period is in seconds; it defaults to 30, the length Google
    Authenticator uses. Changing the grace period, however, will change the
    resulting code, so only use this option if you know what you are doing.

    It is not recommended to use any algorithm but SHA1 unless you know what
    you are doing, due to interoperability concerns.
    """
    if timestamp is None:
        timestamp = int(time())

    # 64-bit timestamps only
    timestamp &= 0xFFFFFFFFFFFFFFFF

    timestamp //= grace_period

    return get_code(secret, timestamp, length, hash_algorithm)


def check_totp(code, secret, timestamp=None, grace_period=30,
               hash_algorithm=HashAlgorithm.SHA1, below=30, above=30,
               constant_time=True):
    """Check if the given TOTP code matches the given timestamp.

    If timestamp is None, the current system time will be used. Beware though:
    it is important to have accurate system time.

    The grace period is in seconds; it defaults to 30, the length Google
    Authenticator uses. Changing the grace period, however, will change the
    resulting code, so only use this option if you know what you are doing.
    Note this has nothing to do with below and above, which are separate
    options; below and above specify a range, whereas the grace period is
    a factor the time is divided by.

    It is not recommended to use any algorithm but SHA1 unless you know what
    you are doing, due to interoperability concerns.

    below and above specify values less than and greater than the timestamp to
    check, respectively. For example, given Unix time 500, with above and below
    at 10, it will check 490 and 510 as well. This is to account for client
    clock drift as well as "not being fast enough" to put in their code.

    constant_time determines if a constant time string comparison is used, to
    help mitigate timing attacks.
    """
    if timestamp is None:
        timestamp = int(time())

    # 64-bit timestamps only
    timestamp &= 0xFFFFFFFFFFFFFFFF

    start = timestamp - below
    end = timestamp + above

    if start < 0:
        start = 0

    # Cap at 64 bits
    end &= 0xFFFFFFFFFFFFFFFF

    start //= grace_period
    end //= grace_period

    if constant_time:
        return check_range_constant(code, secret, hash_algorithm, start, end)
    else:
        return check_range(code, secret, hash_algorithm, start, end)
