# Copyright (C) 2018 Elizabeth Myers. All rights reserved.
# See the included LICENSE file for terms of distribution.

from unittest import TestCase, skip

from pyotp import totp
from pyotp.constants import HashAlgorithm


class TestTOTPGeneration(TestCase):
    # Test vectors taken from RFC 6238
    secret_algo = {
        HashAlgorithm.SHA1: b"12345678901234567890",
        HashAlgorithm.SHA256: b"12345678901234567890123456789012",
        HashAlgorithm.SHA512: b"1234567890123456789012345678901234567890" \
                              b"123456789012345678901234",
    }

    tests = [
        (59, "94287082", HashAlgorithm.SHA1),
        (59, "46119246", HashAlgorithm.SHA256),
        (59, "90693936", HashAlgorithm.SHA512),
        (1111111109, "07081804", HashAlgorithm.SHA1),
        (1111111109, "68084774", HashAlgorithm.SHA256),
        (1111111109, "25091201", HashAlgorithm.SHA512),
        (1111111111, "14050471", HashAlgorithm.SHA1),
        (1111111111, "67062674", HashAlgorithm.SHA256),
        (1111111111, "99943326", HashAlgorithm.SHA512),
        (1234567890, "89005924", HashAlgorithm.SHA1),
        (1234567890, "91819424", HashAlgorithm.SHA256),
        (1234567890, "93441116", HashAlgorithm.SHA512),
        (2000000000, "69279037", HashAlgorithm.SHA1),
        (2000000000, "90698825", HashAlgorithm.SHA256),
        (2000000000, "38618901", HashAlgorithm.SHA512),
        (20000000000, "65353130", HashAlgorithm.SHA1),
        (20000000000, "77737706", HashAlgorithm.SHA256),
        (20000000000, "47863826", HashAlgorithm.SHA512),
    ]

    def test_totp_generate(self):
        """Ensure TOTP generation works correctly."""
        for (time, expected, algorithm) in self.tests:
            secret = self.secret_algo[algorithm]

            s = totp.get_totp_code(secret, time, length=len(expected),
                                   hash_algorithm=algorithm)
            with self.subTest(secret=secret, time=time,
                              algorithm=algorithm, expected=expected, got=s):
                self.assertEqual(s, expected)

    def test_totp_check_valid(self):
        """Ensure TOTP range checks work correctly."""
        for (time, code, algorithm) in self.tests:
            secret = self.secret_algo[algorithm]

            check = totp.check_totp(code, secret, time,
                                    hash_algorithm=algorithm)
            with self.subTest(secret=secret, time=time, code=code,
                              algorithm=algorithm, check=check,
                              msg="Ensure matching code is accepted"):
                self.assertTrue(check)

    def test_totp_check_valid_below(self):
        """Ensure TOTP range checks work correctly for values below window"""
        for (time, code, algorithm) in self.tests:
            secret = self.secret_algo[algorithm]

            time -= 30
            print("time/expected/algorithm", time, code, algorithm)
            check = totp.check_totp(code, secret, time,
                                    hash_algorithm=algorithm)
            with self.subTest(secret=secret, time=time, code=code,
                              algorithm=algorithm, check=check):
                self.assertTrue(check)

    def test_totp_check_valid_above(self):
        """Ensure TOTP range checks work correctly for values above window"""
        for (time, code, algorithm) in self.tests:
            secret = self.secret_algo[algorithm]

            time += 30
            check = totp.check_totp(code, secret, time, below=0, above=30,
                                    hash_algorithm=algorithm)
            with self.subTest(secret=secret, time=time, code=code,
                              algorithm=algorithm, check=check):
                self.assertTrue(check)

    def test_totp_check_invalid(self):
        """Ensure incorrect codes are rejected."""
        test = self.tests[0]
        secret = self.secret_algo[test[2]]

        check = totp.check_totp(test[1], secret, test[0]+120,
                                hash_algorithm=test[2])
        with self.subTest(secret=secret, check=check, time=test[0]+120,
                          msg="Ensure time below range is rejected"):
            self.assertFalse(check)
        
        check = totp.check_totp(test[1], secret, test[0]-120,
                                hash_algorithm=test[2])
        with self.subTest(secret=secret, check=check, time=test[0]-120,
                          msg="Ensure time below range is rejected"):
            self.assertFalse(check)
        
        check = totp.check_totp("00000000", secret, test[0],
                                hash_algorithm=test[2])
        with self.subTest(secret=secret, check=check, time=test[0],
                           msg="Ensure invalid secret is rejected"):
            self.assertFalse(check)
