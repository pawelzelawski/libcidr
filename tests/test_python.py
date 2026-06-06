"""
test_python.py -- Python binding tests for libcidr.

Phase 7.1: Module skeleton and exception hierarchy.
Verifies module imports, exception inheritance, multi-level catching,
and module-level constant values.

See ARCHITECTURE.md §8.5 for the exception hierarchy specification.
See TESTING.md §7.1 for the full Python test catalogue (expanded in
later phases).
"""

import unittest
import libcidr


class TestModuleImports(unittest.TestCase):
    """Verify the module imports and basic attributes."""

    def test_module_imports(self):
        self.assertIsNotNone(libcidr)
        self.assertTrue(hasattr(libcidr, 'CIDRError'))
        self.assertTrue(hasattr(libcidr, 'AF_INET'))


class TestExceptionHierarchy(unittest.TestCase):
    """Verify exception inheritance matches ARCHITECTURE.md §8.5."""

    def test_cidr_error_base(self):
        self.assertTrue(issubclass(libcidr.CIDRError, Exception))

    def test_parse_error_inheritance(self):
        self.assertTrue(issubclass(libcidr.ParseError, libcidr.CIDRError))
        self.assertTrue(issubclass(libcidr.ParseError, ValueError))

    def test_hostbits_error_inheritance(self):
        self.assertTrue(issubclass(libcidr.HostBitsError, libcidr.CIDRError))
        self.assertTrue(issubclass(libcidr.HostBitsError, ValueError))

    def test_prefix_length_error_inheritance(self):
        self.assertTrue(issubclass(
            libcidr.PrefixLengthError, libcidr.CIDRError))
        self.assertTrue(issubclass(
            libcidr.PrefixLengthError, ValueError))

    def test_invalid_argument_error_inheritance(self):
        self.assertTrue(issubclass(
            libcidr.InvalidArgumentError, libcidr.CIDRError))
        self.assertTrue(issubclass(
            libcidr.InvalidArgumentError, ValueError))

    def test_family_error_inheritance(self):
        self.assertTrue(issubclass(libcidr.FamilyError, libcidr.CIDRError))
        self.assertTrue(issubclass(libcidr.FamilyError, TypeError))

    def test_address_overflow_error_inheritance(self):
        self.assertTrue(issubclass(
            libcidr.AddressOverflowError, libcidr.CIDRError))
        self.assertTrue(issubclass(
            libcidr.AddressOverflowError, OverflowError))


class TestExceptionCatching(unittest.TestCase):
    """Verify multi-level catching semantics."""

    def test_catch_cidr_error_base(self):
        with self.assertRaises(libcidr.CIDRError):
            raise libcidr.ParseError("test")

    def test_catch_cidr_error_catches_all(self):
        """CIDRError must catch every libcidr exception."""
        for exc_type in [
            libcidr.ParseError,
            libcidr.HostBitsError,
            libcidr.PrefixLengthError,
            libcidr.InvalidArgumentError,
            libcidr.FamilyError,
            libcidr.AddressOverflowError,
        ]:
            with self.subTest(exc_type=exc_type):
                with self.assertRaises(libcidr.CIDRError):
                    raise exc_type("test")

    def test_parse_error_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise libcidr.ParseError("test")

    def test_hostbits_error_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise libcidr.HostBitsError("test")

    def test_prefix_length_error_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise libcidr.PrefixLengthError("test")

    def test_invalid_argument_error_caught_as_value_error(self):
        with self.assertRaises(ValueError):
            raise libcidr.InvalidArgumentError("test")

    def test_family_error_caught_as_type_error(self):
        with self.assertRaises(TypeError):
            raise libcidr.FamilyError("test")

    def test_address_overflow_caught_as_overflow_error(self):
        with self.assertRaises(OverflowError):
            raise libcidr.AddressOverflowError("test")


class TestModuleConstants(unittest.TestCase):
    """Verify module-level constant values."""

    def test_af_inet(self):
        self.assertEqual(libcidr.AF_INET, 4)

    def test_af_inet6(self):
        self.assertEqual(libcidr.AF_INET6, 6)

    def test_sort_network_asc(self):
        self.assertEqual(libcidr.SORT_NETWORK_ASC, 0)

    def test_sort_pfxlen_desc(self):
        self.assertEqual(libcidr.SORT_PFXLEN_DESC, 1)

    def test_iana_snapshot(self):
        self.assertEqual(libcidr.CIDR_IANA_SNAPSHOT, 20251009)

    def test_cidr_class_global(self):
        self.assertEqual(libcidr.CIDR_CLASS_GLOBAL, 1)

    def test_cidr_class_this_host(self):
        self.assertEqual(libcidr.CIDR_CLASS_THIS_HOST, 1 << 1)

    def test_cidr_class_private(self):
        self.assertEqual(libcidr.CIDR_CLASS_PRIVATE, 1 << 2)

    def test_cidr_class_shared(self):
        self.assertEqual(libcidr.CIDR_CLASS_SHARED, 1 << 3)

    def test_cidr_class_loopback(self):
        self.assertEqual(libcidr.CIDR_CLASS_LOOPBACK, 1 << 4)

    def test_cidr_class_link_local(self):
        self.assertEqual(libcidr.CIDR_CLASS_LINK_LOCAL, 1 << 5)

    def test_cidr_class_ietf_reserved(self):
        self.assertEqual(libcidr.CIDR_CLASS_IETF_RESERVED, 1 << 6)

    def test_cidr_class_documentation(self):
        self.assertEqual(libcidr.CIDR_CLASS_DOCUMENTATION, 1 << 7)

    def test_cidr_class_6to4_relay(self):
        self.assertEqual(libcidr.CIDR_CLASS_6TO4_RELAY, 1 << 8)

    def test_cidr_class_benchmarking(self):
        self.assertEqual(libcidr.CIDR_CLASS_BENCHMARKING, 1 << 9)

    def test_cidr_class_reserved(self):
        self.assertEqual(libcidr.CIDR_CLASS_RESERVED, 1 << 10)

    def test_cidr_class_broadcast(self):
        self.assertEqual(libcidr.CIDR_CLASS_BROADCAST, 1 << 11)

    def test_cidr_class_unspecified(self):
        self.assertEqual(libcidr.CIDR_CLASS_UNSPECIFIED, 1 << 12)

    def test_cidr_class_v4mapped(self):
        self.assertEqual(libcidr.CIDR_CLASS_V4MAPPED, 1 << 13)

    def test_cidr_class_v4translated(self):
        self.assertEqual(libcidr.CIDR_CLASS_V4TRANSLATED, 1 << 14)

    def test_cidr_class_discard(self):
        self.assertEqual(libcidr.CIDR_CLASS_DISCARD, 1 << 15)

    def test_cidr_class_unique_local(self):
        self.assertEqual(libcidr.CIDR_CLASS_UNIQUE_LOCAL, 1 << 16)

    def test_cidr_class_multicast(self):
        self.assertEqual(libcidr.CIDR_CLASS_MULTICAST, 1 << 17)

    def test_cidr_class_anycast(self):
        self.assertEqual(libcidr.CIDR_CLASS_ANYCAST, 1 << 18)

    def test_cidr_class_teredo(self):
        self.assertEqual(libcidr.CIDR_CLASS_TEREDO, 1 << 19)

    def test_cidr_class_6to4(self):
        self.assertEqual(libcidr.CIDR_CLASS_6TO4, 1 << 20)

    def test_cidr_class_orchid(self):
        self.assertEqual(libcidr.CIDR_CLASS_ORCHID, 1 << 21)

    def test_cidr_class_srv6(self):
        self.assertEqual(libcidr.CIDR_CLASS_SRV6, 1 << 22)


if __name__ == '__main__':
    unittest.main()
