# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.

from unittest import TestCase

from pyotp import hotp
from pyotp.constants import HashAlgorithm


class TestHOTPGeneration(TestCase):
    # TODO: other hash algorithms, although not RFC 4226 compliant

    # Test vectors taken from RFC 4226
    secret = b"12345678901234567890"
    codes = [
        "755224",
        "287082",
        "359152",
        "969429",
        "338314",
        "254676",
        "287922",
        "162583",
        "399871",
        "520489"
    ]

    def test_hotp_generate(self):
        """Ensure HOTP generation works correctly."""
        for i, expected in enumerate(self.codes):
            s = hotp.get_hotp_code(self.secret, i, length=6)
            with self.subTest(secret=self.secret, counter=i, expected=expected,
                              got=s):
                self.assertEqual(s, expected)

    def test_hotp_check_valid(self):
        """Ensure HOTP range checks work correctly."""
        for code in self.codes:
            check = hotp.check_hotp(code, self.secret, 0, above=10)
            with self.subTest(secret=self.secret, counter=0, code=code,
                              check=check):
                self.assertTrue(check)

    def test_hotp_check_invalid(self):
        """Ensure incorrect codes are rejected."""
        check = hotp.check_hotp(self.codes[0], self.secret, 1)
        with self.subTest(secret=self.secret, check=check, counter=1,
                          msg="Ensure code below range is rejected"):
            self.assertFalse(check)

        check = hotp.check_hotp(self.codes[2], self.secret, 0, above=2)
        with self.subTest(secret=self.secret, check=check, counter=0,
                          msg = "Ensure code above range is rejected"):
            self.assertFalse(check)

        check = hotp.check_hotp("000000", self.secret, 0)
        with self.subTest(secret=self.secret, check=check, counter=0,
                          msg="Ensure invalid code is rejected"):
            self.assertFalse(check)
