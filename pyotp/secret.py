# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.

import base64

from secrets import token_bytes

from pyotp.constants import SecretEncoding

# Map constants to encoding algorithms
_encoding_map = {
    SecretEncoding.BASE32: base64.b32encode,
    SecretEncoding.BASE64_STD: base64.standard_b64encode,
    SecretEncoding.BASE64_URLSAFE: base64.urlsafe_b64encode,
    SecretEncoding.ASCII85: base64.a85encode,
    SecretEncoding.BASE85: base64.b85encode,
}


# Same as above, but for decoding
_decoding_map = {
    SecretEncoding.BASE32: base64.b32decode,
    SecretEncoding.BASE64_STD: base64.standard_b64decode,
    SecretEncoding.BASE64_URLSAFE: base64.urlsafe_b64decode,
    SecretEncoding.ASCII85: base64.a85decode,
    SecretEncoding.BASE85: base64.b85decode,
}


def make_secret(length=SecretLength.GOOGLE_AUTH):
    """Create a secret of the given byte length."""
    if hasattr(length, "value"):
        length = length.value

    return token_bytes(length)


def encode_secret(secret, encoding=SecretEncoding.BASE32):
    """Encode a secret with the given encoding."""
    return _encoding_map[encoding](secret)


def decode_secret(secret, encoding=SecretEncoding.BASE32):
    """Decode a secret with the given encoding."""
    return _decoding_map[encoding](secret)
