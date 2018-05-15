# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution..

"""Constants used by pyotp."""

from enum import Enum, auto


class SecretLength(Enum):
    """Standard byte lengths for secrets."""

    GOOGLE_AUTH = 10
    """Google Authenticator uses 80-bit secrets (10 bytes)."""

    RFC_4226_MIN = 16
    """RFC 4226 minimum requirement of 128 bits (16 bytes)."""

    RFC_4226_RECOMMEND = 20
    """RFC 4226 recommended secret length of 160 bits (20 bytes)."""


class HashAlgorithm(Enum):
    """Valid hash algorithms for TOTP use (RFC 6238)."""

    SHA1 = "sha1"
    """Default hash algorithm; only one specified by RFC 4226."""

    SHA256 = "sha256"
    """Optional hash specified by RFC 6238, but not widely supported."""

    SHA512 = "sha512"
    """Optional hash specified by RFC 6238, but not widely supported."""


class SecretEncoding(Enum):
    """Valid encodings for secrets."""

    BASE32 = auto()
    """Base32 encoding
    
    Most common encoding and compatible with Google Authenticator."""

    BASE64_STD = auto()
    """Base64 standard encoding; uncommon variant."""

    BASE64_URLSAFE = auto()
    """Base64 URL-safe encoding; uncommon variant."""

    BASE85 = auto()
    """Base85 encoding; very uncommon variant."""

    ASCII85 = auto()
    """Ascii85 encoding; very uncommon variant."""
