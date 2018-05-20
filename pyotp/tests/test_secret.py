# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.

from unittest import TestCase

from pyotp import secret
from pyotp.constants import SecretLength, SecretEncoding


class TestSecretGenerationLength(TestCase):
    def test_length(self):
        """Test that lengths of secrets generated are expected values."""
        # Parameters and expected values
        data = {
            SecretLength.GOOGLE_AUTH: 10,
            SecretLength.RFC_4226_MIN: 16,
            SecretLength.RFC_4226_RECOMMEND: 20,
            1: 1
        }

        for param, length in data.items():
            with self.subTest(param=param, length=length):
                s = secret.make_secret(param)
                self.assertEqual(len(s), length)

    def test_default_length(self):
        """Ensure default length is the Google authenticator length"""
        s = secret.make_secret()
        self.assertEqual(len(s), SecretLength.GOOGLE_AUTH.value)


# Test data for encoding and decoding
# format:
# encoding: { (byte, size): expected value, ... }
test_data = {
    SecretEncoding.BASE32: {
        (b"\x00", SecretLength.GOOGLE_AUTH):
            b"AAAAAAAAAAAAAAAA",
        (b"\x00", SecretLength.RFC_4226_MIN):
            b"AAAAAAAAAAAAAAAAAAAAAAAAAA======",
        (b"\x00", SecretLength.RFC_4226_RECOMMEND):
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
    SecretEncoding.BASE64_STD: {
        (b"\xfa", SecretLength.GOOGLE_AUTH):
            b"+vr6+vr6+vr6+g==",
        (b"\xfa", SecretLength.RFC_4226_MIN):
            b"+vr6+vr6+vr6+vr6+vr6+g==",
        (b"\xfa", SecretLength.RFC_4226_RECOMMEND):
            b"+vr6+vr6+vr6+vr6+vr6+vr6+vo=",
    },
    SecretEncoding.BASE64_URLSAFE: {
        (b"\xfa", SecretLength.GOOGLE_AUTH):
            b"-vr6-vr6-vr6-g==",
        (b"\xfa", SecretLength.RFC_4226_MIN):
            b"-vr6-vr6-vr6-vr6-vr6-g==",
        (b"\xfa", SecretLength.RFC_4226_RECOMMEND):
            b"-vr6-vr6-vr6-vr6-vr6-vr6-vo=",
    },
    SecretEncoding.BASE85: {
        (b"\xfa", SecretLength.GOOGLE_AUTH):
            b"`uh6%`uh6%`uY",
        (b"\xfa", SecretLength.RFC_4226_MIN):
            b"`uh6%`uh6%`uh6%`uh6%",
        (b"\xfa", SecretLength.RFC_4226_RECOMMEND):
            b"`uh6%`uh6%`uh6%`uh6%`uh6%",
    },
    SecretEncoding.ASCII85: {
        (b"\xfa", SecretLength.GOOGLE_AUTH):
            b"qYL'bqYL'bqYC",
        (b"\xfa", SecretLength.RFC_4226_MIN):
            b"qYL'bqYL'bqYL'bqYL'b",
        (b"\xfa", SecretLength.RFC_4226_RECOMMEND):
            b"qYL'bqYL'bqYL'bqYL'bqYL'b",
    },
}

class TestSecretEncoding(TestCase):
    def test_encoding(self):
        """Test that encoding of secrets is correct"""
        for encoding, val in test_data.items():
            for (test_byte, length), expected in val.items():
                if hasattr(length, "value"):
                    test_str = test_byte * length.value
                else:
                    test_str = test_byte * length

                with self.subTest(encoding=encoding, test_str=test_str,
                                  expected=expected):
                    s = secret.encode_secret(test_str, encoding)
                    self.assertEqual(s, expected)

    def test_default_encoding(self):
        """Test that the default encoding is base32"""
        test_str = b"\x00" * SecretLength.GOOGLE_AUTH.value
        s = secret.encode_secret(test_str)
        self.assertEqual(s, b"AAAAAAAAAAAAAAAA")


class TestSecretDecoding(TestCase):
    # TODO: test invalid strings in decoding
    def test_decoding(self):
        """Test that decoding of secrets is correct"""
        for encoding, val in test_data.items():
            for (test_byte, length), decode in val.items():
                if hasattr(length, "value"):
                    expected = test_byte * length.value
                else:
                    expected = test_byte * length

                s = secret.decode_secret(decode, encoding)
                with self.subTest(encoding=encoding, expected=expected, got=s):
                    self.assertEqual(s, expected)

    def test_default_decoding(self):
        """Test that the default decoding is base32"""
        test_str = b"\x00" * SecretLength.GOOGLE_AUTH.value
        s = secret.decode_secret(b"AAAAAAAAAAAAAAAA")
        self.assertEqual(s, test_str)
