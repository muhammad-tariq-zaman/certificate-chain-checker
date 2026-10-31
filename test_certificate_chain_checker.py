import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from datetime import date
from main import check_chain, split_pem

LEAF = {"subject": ("leaf",), "issuer": ("ca",), "not_after": date(2027, 1, 1)}
CA = {"subject": ("ca",), "issuer": ("ca",), "not_after": date(2028, 1, 1)}
TODAY = date(2026, 10, 30)


class TestChainChecker(unittest.TestCase):
    def test_valid_chain_ok(self):
        self.assertEqual(check_chain([LEAF, CA], TODAY), [])

    def test_broken_link_flagged(self):
        other = {"subject": ("other",), "issuer": ("other",), "not_after": date(2028, 1, 1)}
        problems = check_chain([LEAF, other], TODAY)
        self.assertTrue(any("chain broken" in p for p in problems))

    def test_expired_flagged(self):
        old = {"subject": ("leaf",), "issuer": ("ca",), "not_after": date(2020, 1, 1)}
        self.assertTrue(any("EXPIRED" in p for p in check_chain([old, CA], TODAY)))

    def test_split_pem_counts_blocks(self):
        pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
        self.assertEqual(len(split_pem(pem)), 2)
