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


class TestAddressConstructors(unittest.TestCase):
    """Verify IPv4Address and IPv6Address constructors per ARCHITECTURE.md §8.6."""

    def test_ipv4_string_constructor(self):
        cases = [
            ('192.168.1.1', '192.168.1.1'),
            ('0.0.0.0', '0.0.0.0'),
            ('255.255.255.255', '255.255.255.255'),
            ('10.0.0.1', '10.0.0.1'),
            ('127.0.0.1', '127.0.0.1'),
        ]
        for s, expected in cases:
            with self.subTest(s=s):
                addr = libcidr.IPv4Address(s)
                self.assertEqual(str(addr), expected)

    def test_ipv6_string_constructor(self):
        cases = [
            ('::1', '::1'),
            ('2001:db8::1', '2001:db8::1'),
            ('::', '::'),
            ('::ffff:192.0.2.1', '::ffff:192.0.2.1'),
            ('fe80::1', 'fe80::1'),
            ('ff02::1', 'ff02::1'),
        ]
        for s, expected in cases:
            with self.subTest(s=s):
                addr = libcidr.IPv6Address(s)
                self.assertEqual(str(addr), expected)

    def test_ipv4_bytes_constructor(self):
        addr = libcidr.IPv4Address(b'\xc0\xa8\x01\x01')
        self.assertEqual(str(addr), '192.168.1.1')
        self.assertEqual(addr.packed, b'\xc0\xa8\x01\x01')

    def test_ipv6_bytes_constructor(self):
        packed = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        addr = libcidr.IPv6Address(packed)
        self.assertEqual(str(addr), '2001:db8::1')
        self.assertEqual(addr.packed, packed)

    def test_ipv4_int_constructor(self):
        cases = [
            (0, '0.0.0.0'),
            (4294967295, '255.255.255.255'),
            (16909060, '1.2.3.4'),
            (3232235777, '192.168.1.1'),
        ]
        for val, expected in cases:
            with self.subTest(val=val):
                addr = libcidr.IPv4Address(val)
                self.assertEqual(str(addr), expected)

    def test_ipv6_int_constructor(self):
        cases = [
            (0, '::'),
            (1, '::1'),
            (2**128 - 1, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
        ]
        for val, expected in cases:
            with self.subTest(val=val):
                addr = libcidr.IPv6Address(val)
                self.assertEqual(str(addr), expected)

    def test_ipv4_from_ipaddress_object(self):
        import ipaddress
        src = ipaddress.IPv4Address('10.0.0.1')
        addr = libcidr.IPv4Address(src)
        self.assertEqual(str(addr), '10.0.0.1')
        self.assertEqual(addr.packed, src.packed)

    def test_ipv6_from_ipaddress_object(self):
        import ipaddress
        src = ipaddress.IPv6Address('fe80::1')
        addr = libcidr.IPv6Address(src)
        self.assertEqual(str(addr), 'fe80::1')
        self.assertEqual(addr.packed, src.packed)


class TestAddressFamilyMismatch(unittest.TestCase):
    """Verify family mismatch raises FamilyError."""

    def test_ipv6_string_to_ipv4(self):
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv4Address('::1')

    def test_ipv4_string_to_ipv6(self):
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv6Address('192.168.1.1')

    def test_16byte_bytes_to_ipv4(self):
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv4Address(b'\x00' * 16)

    def test_4byte_bytes_to_ipv6(self):
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv6Address(b'\x00' * 4)

    def test_ipv6_address_object_to_ipv4(self):
        import ipaddress
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv4Address(ipaddress.IPv6Address('::1'))

    def test_ipv4_address_object_to_ipv6(self):
        import ipaddress
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv6Address(ipaddress.IPv4Address('1.2.3.4'))


class TestAddressInvalidInput(unittest.TestCase):
    """Verify invalid input raises appropriate exceptions."""

    def test_invalid_string_raises_parse_error(self):
        with self.assertRaises(libcidr.ParseError):
            libcidr.IPv4Address('not an address')

    def test_empty_string_raises_error(self):
        with self.assertRaises(libcidr.ParseError):
            libcidr.IPv4Address('')

    def test_bytes_wrong_length_raises_error(self):
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv4Address(b'\x00')
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv6Address(b'\x00' * 3)

    def test_negative_int_raises_value_error(self):
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv4Address(-1)
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv6Address(-1)

    def test_int_too_large_raises_error(self):
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv4Address(2**32)
        with self.assertRaises(libcidr.InvalidArgumentError):
            libcidr.IPv6Address(2**128)

    def test_invalid_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            libcidr.IPv4Address([1, 2, 3, 4])
        with self.assertRaises(TypeError):
            libcidr.IPv4Address(3.14)
        with self.assertRaises(TypeError):
            libcidr.IPv6Address(None)


class TestAddressProperties(unittest.TestCase):
    """Verify property accessors return correct values."""

    def test_packed(self):
        import ipaddress
        cases = [
            (libcidr.IPv4Address('1.2.3.4'), ipaddress.IPv4Address('1.2.3.4').packed),
            (libcidr.IPv4Address('0.0.0.0'), ipaddress.IPv4Address('0.0.0.0').packed),
            (libcidr.IPv6Address('::1'), ipaddress.IPv6Address('::1').packed),
            (libcidr.IPv6Address('2001:db8::1'), ipaddress.IPv6Address('2001:db8::1').packed),
        ]
        for addr, expected in cases:
            with self.subTest(addr=str(addr)):
                self.assertEqual(addr.packed, expected)

    def test_compressed(self):
        import ipaddress
        cases = [
            (libcidr.IPv4Address('1.2.3.4'), ipaddress.IPv4Address('1.2.3.4').compressed),
            (libcidr.IPv4Address('192.168.1.1'), ipaddress.IPv4Address('192.168.1.1').compressed),
            (libcidr.IPv6Address('::1'), ipaddress.IPv6Address('::1').compressed),
            (libcidr.IPv6Address('2001:db8::1'), ipaddress.IPv6Address('2001:db8::1').compressed),
        ]
        for addr, expected in cases:
            with self.subTest(addr=str(addr)):
                self.assertEqual(addr.compressed, expected)

    def test_exploded(self):
        import ipaddress
        cases = [
            (libcidr.IPv4Address('1.2.3.4'), ipaddress.IPv4Address('1.2.3.4').exploded),
            (libcidr.IPv6Address('::1'), ipaddress.IPv6Address('::1').exploded),
            (libcidr.IPv6Address('2001:db8::1'),
             ipaddress.IPv6Address('2001:db8::1').exploded),
        ]
        for addr, expected in cases:
            with self.subTest(addr=str(addr)):
                self.assertEqual(addr.exploded, expected)

    def test_version(self):
        self.assertEqual(libcidr.IPv4Address('1.2.3.4').version, 4)
        self.assertEqual(libcidr.IPv6Address('::1').version, 6)

    def test_is_global(self):
        self.assertTrue(libcidr.IPv4Address('8.8.8.8').is_global)
        self.assertFalse(libcidr.IPv4Address('10.0.0.1').is_global)
        self.assertFalse(libcidr.IPv6Address('2001:db8::1').is_global)
        self.assertFalse(libcidr.IPv6Address('fe80::1').is_global)
        self.assertTrue(libcidr.IPv6Address('2001:470::1').is_global)

    def test_is_private(self):
        self.assertTrue(libcidr.IPv4Address('10.0.0.1').is_private)
        self.assertFalse(libcidr.IPv4Address('8.8.8.8').is_private)
        self.assertFalse(libcidr.IPv6Address('2001:db8::1').is_private)

    def test_is_loopback(self):
        self.assertTrue(libcidr.IPv4Address('127.0.0.1').is_loopback)
        self.assertTrue(libcidr.IPv6Address('::1').is_loopback)
        self.assertFalse(libcidr.IPv4Address('1.2.3.4').is_loopback)

    def test_is_multicast(self):
        self.assertTrue(libcidr.IPv4Address('224.0.0.1').is_multicast)
        self.assertTrue(libcidr.IPv6Address('ff02::1').is_multicast)
        self.assertFalse(libcidr.IPv4Address('1.2.3.4').is_multicast)
        self.assertFalse(libcidr.IPv6Address('2001:db8::1').is_multicast)

    def test_is_link_local(self):
        self.assertTrue(libcidr.IPv4Address('169.254.1.1').is_link_local)
        self.assertTrue(libcidr.IPv6Address('fe80::1').is_link_local)
        self.assertFalse(libcidr.IPv4Address('1.2.3.4').is_link_local)

    def test_is_unspecified(self):
        self.assertFalse(libcidr.IPv4Address('0.0.0.0').is_unspecified)
        self.assertTrue(libcidr.IPv6Address('::').is_unspecified)
        self.assertFalse(libcidr.IPv6Address('::1').is_unspecified)


class TestAddressMethods(unittest.TestCase):
    """Verify address instance methods."""

    def test_classify_returns_int(self):
        addr = libcidr.IPv4Address('192.0.2.1')
        result = addr.classify()
        self.assertIsInstance(result, int)
        self.assertTrue(result & libcidr.CIDR_CLASS_DOCUMENTATION)

    def test_classify_v4_private(self):
        addr = libcidr.IPv4Address('10.0.0.1')
        result = addr.classify()
        self.assertTrue(result & libcidr.CIDR_CLASS_PRIVATE)

    def test_classify_v4_loopback(self):
        addr = libcidr.IPv4Address('127.0.0.1')
        result = addr.classify()
        self.assertTrue(result & libcidr.CIDR_CLASS_LOOPBACK)

    def test_classify_v6_loopback(self):
        addr = libcidr.IPv6Address('::1')
        result = addr.classify()
        self.assertTrue(result & libcidr.CIDR_CLASS_LOOPBACK)

    def test_to_ipv4_mapped_returns_ipv4(self):
        addr = libcidr.IPv6Address('::ffff:192.0.2.1')
        result = addr.to_ipv4()
        self.assertIsInstance(result, libcidr.IPv4Address)
        self.assertEqual(str(result), '192.0.2.1')

    def test_to_ipv4_non_mapped_returns_none(self):
        addr = libcidr.IPv6Address('2001:db8::1')
        self.assertIsNone(addr.to_ipv4())

    def test_to_ipv4_not_on_ipv4(self):
        addr = libcidr.IPv4Address('1.2.3.4')
        self.assertFalse(hasattr(addr, 'to_ipv4'))

    def test_classify_on_ipv6(self):
        addr = libcidr.IPv6Address('::ffff:192.0.2.1')
        result = addr.classify()
        self.assertTrue(result & libcidr.CIDR_CLASS_V4MAPPED)


class TestAddressProtocol(unittest.TestCase):
    """Verify Python protocol methods: __str__, __repr__, __eq__, __hash__, __lt__, dict/set."""

    def test_str_equals_compressed(self):
        v4 = libcidr.IPv4Address('1.2.3.4')
        v6 = libcidr.IPv6Address('2001:db8::1')
        self.assertEqual(str(v4), v4.compressed)
        self.assertEqual(str(v6), v6.compressed)

    def test_repr_ipv4(self):
        addr = libcidr.IPv4Address('1.2.3.4')
        self.assertEqual(repr(addr), "IPv4Address('1.2.3.4')")

    def test_repr_ipv6(self):
        addr = libcidr.IPv6Address('::1')
        self.assertEqual(repr(addr), "IPv6Address('::1')")

    def test_eq_equal(self):
        a = libcidr.IPv4Address('1.2.3.4')
        b = libcidr.IPv4Address('1.2.3.4')
        self.assertEqual(a, b)

    def test_eq_not_equal(self):
        a = libcidr.IPv4Address('1.2.3.4')
        b = libcidr.IPv4Address('5.6.7.8')
        self.assertNotEqual(a, b)

    def test_eq_cross_family_raises_family_error(self):
        v4 = libcidr.IPv4Address('1.2.3.4')
        v6 = libcidr.IPv6Address('::1')
        with self.assertRaises(libcidr.FamilyError):
            v4 == v6
        with self.assertRaises(libcidr.FamilyError):
            v6 == v4

    def test_hash_equal(self):
        a = libcidr.IPv4Address('1.2.3.4')
        b = libcidr.IPv4Address('1.2.3.4')
        self.assertEqual(hash(a), hash(b))

    def test_lt_ordering_ipv4(self):
        import ipaddress
        ips = ['1.2.3.4', '5.6.7.8', '10.0.0.1', '192.168.1.1', '8.8.8.8']
        libcidr_addrs = [libcidr.IPv4Address(s) for s in ips]
        ipaddr_addrs = [ipaddress.IPv4Address(s) for s in ips]
        sorted_libcidr = [str(a) for a in sorted(libcidr_addrs)]
        sorted_ipaddr = [str(a) for a in sorted(ipaddr_addrs)]
        self.assertEqual(sorted_libcidr, sorted_ipaddr)

    def test_lt_ordering_ipv6(self):
        import ipaddress
        ips = ['::1', '::2', '2001:db8::1', 'fe80::1', 'ff02::1']
        libcidr_addrs = [libcidr.IPv6Address(s) for s in ips]
        ipaddr_addrs = [ipaddress.IPv6Address(s) for s in ips]
        sorted_libcidr = [str(a) for a in sorted(libcidr_addrs)]
        sorted_ipaddr = [str(a) for a in sorted(ipaddr_addrs)]
        self.assertEqual(sorted_libcidr, sorted_ipaddr)

    def test_lt_cross_family(self):
        v4 = libcidr.IPv4Address('1.2.3.4')
        v6 = libcidr.IPv6Address('::1')
        with self.assertRaises(libcidr.FamilyError):
            v4 < v6
        with self.assertRaises(libcidr.FamilyError):
            v6 < v4

    def test_usable_as_dict_key(self):
        addr = libcidr.IPv4Address('1.2.3.4')
        d = {addr: 'test'}
        self.assertEqual(d[libcidr.IPv4Address('1.2.3.4')], 'test')

    def test_usable_in_set(self):
        addr = libcidr.IPv4Address('1.2.3.4')
        s = {addr, libcidr.IPv4Address('1.2.3.4')}
        self.assertEqual(len(s), 1)


class TestAddressEdgeCases(unittest.TestCase):
    """Verify round-trip and edge-case behavior."""

    def test_ipv4_zero_round_trip(self):
        s = '0.0.0.0'
        addr = libcidr.IPv4Address(s)
        self.assertEqual(str(addr), s)
        self.assertEqual(repr(addr), "IPv4Address('0.0.0.0')")
        self.assertEqual(addr.packed, b'\x00' * 4)

    def test_ipv4_max_round_trip(self):
        s = '255.255.255.255'
        addr = libcidr.IPv4Address(s)
        self.assertEqual(str(addr), s)
        self.assertEqual(addr.packed, b'\xff' * 4)

    def test_ipv6_full_notation_round_trip(self):
        s = '2001:0db8:0000:0000:0000:0000:0000:0001'
        addr = libcidr.IPv6Address(s)
        self.assertEqual(str(addr), '2001:db8::1')

    def test_ipv4_mapped_ipv6_stored_as_ipv6(self):
        addr = libcidr.IPv6Address('::ffff:192.0.2.1')
        self.assertIsInstance(addr, libcidr.IPv6Address)
        self.assertEqual(addr.version, 6)
        self.assertEqual(str(addr), '::ffff:192.0.2.1')

    def test_ipv6_zero_round_trip(self):
        s = '::'
        addr = libcidr.IPv6Address(s)
        self.assertEqual(str(addr), s)
        self.assertEqual(addr.packed, b'\x00' * 16)
        self.assertTrue(addr.is_unspecified)


class TestAddressIpaddressComparison(unittest.TestCase):
    """Compare libcidr properties against stdlib ipaddress for consistency."""

    def _check_v4(self, addr_str):
        import ipaddress
        l = libcidr.IPv4Address(addr_str)
        i = ipaddress.IPv4Address(addr_str)
        with self.subTest(addr=addr_str, prop='packed'):
            self.assertEqual(l.packed, i.packed)
        with self.subTest(addr=addr_str, prop='compressed'):
            self.assertEqual(l.compressed, i.compressed)
        with self.subTest(addr=addr_str, prop='version'):
            self.assertEqual(l.version, i.version)
        with self.subTest(addr=addr_str, prop='is_loopback'):
            self.assertEqual(l.is_loopback, i.is_loopback)
        with self.subTest(addr=addr_str, prop='is_multicast'):
            self.assertEqual(l.is_multicast, i.is_multicast)
        with self.subTest(addr=addr_str, prop='is_link_local'):
            self.assertEqual(l.is_link_local, i.is_link_local)

    def test_ipv4_properties(self):
        cases = [
            '8.8.8.8',
            '10.0.0.1',
            '127.0.0.1',
            '192.168.1.1',
            '169.254.1.1',
            '224.0.0.1',
            '192.0.2.1',
            '0.0.0.0',
            '255.255.255.255',
        ]
        for s in cases:
            self._check_v4(s)

    def _check_v6(self, addr_str):
        import ipaddress
        l = libcidr.IPv6Address(addr_str)
        i = ipaddress.IPv6Address(addr_str)
        with self.subTest(addr=addr_str, prop='packed'):
            self.assertEqual(l.packed, i.packed)
        with self.subTest(addr=addr_str, prop='compressed'):
            self.assertEqual(l.compressed, i.compressed)
        with self.subTest(addr=addr_str, prop='version'):
            self.assertEqual(l.version, i.version)
        with self.subTest(addr=addr_str, prop='is_loopback'):
            self.assertEqual(l.is_loopback, i.is_loopback)
        with self.subTest(addr=addr_str, prop='is_multicast'):
            self.assertEqual(l.is_multicast, i.is_multicast)
        with self.subTest(addr=addr_str, prop='is_link_local'):
            self.assertEqual(l.is_link_local, i.is_link_local)

    def test_ipv6_properties(self):
        cases = [
            '::1',
            'fe80::1',
            'ff02::1',
            '2001:db8::1',
            '::',
            '::ffff:192.0.2.1',
            '2001:0db8:0000:0000:0000:0000:0000:0001',
        ]
        for s in cases:
            self._check_v6(s)


class TestNetworkConstructors(unittest.TestCase):
    """Verify IPv4Network and IPv6Network constructors per ARCHITECTURE.md §8.7."""

    def test_ipv4_string_strict(self):
        cases = [
            '192.168.1.0/24',
            '10.0.0.0/8',
            '0.0.0.0/0',
            '255.255.255.255/32',
            '172.16.0.0/12',
        ]
        for s in cases:
            with self.subTest(s=s):
                net = libcidr.IPv4Network(s)
                self.assertEqual(str(net), s)

    def test_ipv6_string_strict(self):
        cases = [
            '2001:db8::/32',
            '::/0',
            '::1/128',
            'fe80::/10',
            '2001:db8:dead::/48',
        ]
        for s in cases:
            with self.subTest(s=s):
                net = libcidr.IPv6Network(s)
                self.assertEqual(str(net), s)

    def test_ipv4_string_hostbits_strict(self):
        with self.assertRaises(libcidr.HostBitsError):
            libcidr.IPv4Network('192.168.1.5/24')

    def test_ipv6_string_hostbits_strict(self):
        with self.assertRaises(libcidr.HostBitsError):
            libcidr.IPv6Network('2001:db8::1/32')

    def test_ipv4_string_not_strict(self):
        net = libcidr.IPv4Network('192.168.1.5/24', strict=False)
        self.assertEqual(str(net), '192.168.1.0/24')

    def test_ipv6_string_not_strict(self):
        net = libcidr.IPv6Network('2001:db8::1/32', strict=False)
        self.assertEqual(str(net), '2001:db8::/32')

    def test_ipv4_tuple_strict(self):
        net = libcidr.IPv4Network(('10.0.0.0', 8))
        self.assertEqual(str(net), '10.0.0.0/8')

    def test_ipv6_tuple_strict(self):
        net = libcidr.IPv6Network(('2001:db8::', 32))
        self.assertEqual(str(net), '2001:db8::/32')

    def test_ipv4_tuple_hostbits_strict(self):
        with self.assertRaises(libcidr.HostBitsError):
            libcidr.IPv4Network(('192.168.1.5', 24))

    def test_ipv4_tuple_not_strict(self):
        net = libcidr.IPv4Network(('192.168.1.5', 24), strict=False)
        self.assertEqual(str(net), '192.168.1.0/24')

    def test_ipv6_tuple_not_strict(self):
        net = libcidr.IPv6Network(('2001:db8::1', 32), strict=False)
        self.assertEqual(str(net), '2001:db8::/32')

    def test_ipv4_from_ipaddress(self):
        import ipaddress
        src = ipaddress.IPv4Network('10.0.0.0/8')
        net = libcidr.IPv4Network(src)
        self.assertEqual(str(net), '10.0.0.0/8')
        self.assertEqual(net.prefixlen, 8)

    def test_ipv6_from_ipaddress(self):
        import ipaddress
        src = ipaddress.IPv6Network('2001:db8::/32')
        net = libcidr.IPv6Network(src)
        self.assertEqual(str(net), '2001:db8::/32')
        self.assertEqual(net.prefixlen, 32)

    def test_ipv4_from_ipaddress_strict_ignored(self):
        import ipaddress
        src = ipaddress.IPv4Network('10.0.0.0/8')
        net = libcidr.IPv4Network(src, strict=False)
        self.assertEqual(str(net), '10.0.0.0/8')
        net2 = libcidr.IPv4Network(src, strict=True)
        self.assertEqual(str(net2), '10.0.0.0/8')

    def test_ipv4_cross_family_string(self):
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv4Network('::/0')

    def test_ipv6_cross_family_string(self):
        with self.assertRaises(libcidr.FamilyError):
            libcidr.IPv6Network('0.0.0.0/0')


class TestNetworkProperties(unittest.TestCase):
    """Verify network property accessors per ARCHITECTURE.md §8.7.2."""

    def test_network_address_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        addr = net.network_address
        self.assertIsInstance(addr, libcidr.IPv4Address)
        self.assertEqual(str(addr), '192.168.1.0')

    def test_network_address_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        addr = net.network_address
        self.assertIsInstance(addr, libcidr.IPv6Address)
        self.assertEqual(str(addr), '2001:db8::')

    def test_broadcast_address_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        bcast = net.broadcast_address
        self.assertIsInstance(bcast, libcidr.IPv4Address)
        self.assertEqual(str(bcast), '192.168.1.255')

    def test_broadcast_address_v4_zero(self):
        net = libcidr.IPv4Network('0.0.0.0/0')
        bcast = net.broadcast_address
        self.assertEqual(str(bcast), '255.255.255.255')

    def test_broadcast_address_v4_32(self):
        net = libcidr.IPv4Network('192.168.1.1/32')
        bcast = net.broadcast_address
        self.assertEqual(str(bcast), '192.168.1.1')

    def test_broadcast_address_v6_raises(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        with self.assertRaises(libcidr.FamilyError):
            net.broadcast_address

    def test_prefixlen_v4(self):
        self.assertEqual(libcidr.IPv4Network('10.0.0.0/8').prefixlen, 8)
        self.assertEqual(libcidr.IPv4Network('0.0.0.0/0').prefixlen, 0)
        self.assertEqual(libcidr.IPv4Network('192.168.1.0/24').prefixlen, 24)
        self.assertEqual(
            libcidr.IPv4Network('192.168.1.1/32').prefixlen, 32)

    def test_prefixlen_v6(self):
        self.assertEqual(libcidr.IPv6Network('::/0').prefixlen, 0)
        self.assertEqual(
            libcidr.IPv6Network('2001:db8::/32').prefixlen, 32)
        self.assertEqual(libcidr.IPv6Network('::1/128').prefixlen, 128)

    def test_netmask_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        mask = net.netmask
        self.assertIsInstance(mask, libcidr.IPv4Address)
        self.assertEqual(str(mask), '255.255.255.0')

    def test_netmask_v4_zero(self):
        net = libcidr.IPv4Network('0.0.0.0/0')
        self.assertEqual(str(net.netmask), '0.0.0.0')

    def test_netmask_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        mask = net.netmask
        self.assertIsInstance(mask, libcidr.IPv6Address)
        self.assertEqual(str(mask), 'ffff:ffff::')

    def test_with_prefixlen_v4(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        self.assertEqual(net.with_prefixlen, '10.0.0.0/8')

    def test_with_prefixlen_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        self.assertEqual(net.with_prefixlen, '2001:db8::/32')

    def test_version_v4(self):
        self.assertEqual(libcidr.IPv4Network('0.0.0.0/0').version, 4)

    def test_version_v6(self):
        self.assertEqual(libcidr.IPv6Network('::/0').version, 6)

    def test_num_addresses_v4(self):
        cases = [
            ('0.0.0.0/0', 2**32),
            ('192.168.0.0/24', 256),
            ('10.0.0.0/8', 2**24),
            ('192.168.1.0/31', 2),
            ('192.168.1.1/32', 1),
        ]
        for s, expected in cases:
            with self.subTest(s=s):
                self.assertEqual(
                    libcidr.IPv4Network(s).num_addresses, expected)

    def test_num_addresses_v6(self):
        net = libcidr.IPv6Network('2001:db8::/120')
        self.assertEqual(net.num_addresses, 256)
        net2 = libcidr.IPv6Network('::1/128')
        self.assertEqual(net2.num_addresses, 1)
        net3 = libcidr.IPv6Network('::/0')
        self.assertEqual(net3.num_addresses, 2**128)


class TestNetworkMethods(unittest.TestCase):
    """Verify network methods per ARCHITECTURE.md §8.7.3."""

    def test_overlaps_true(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.1.0.0/16')
        self.assertTrue(a.overlaps(b))
        self.assertTrue(b.overlaps(a))

    def test_overlaps_false(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('192.168.0.0/16')
        self.assertFalse(a.overlaps(b))
        self.assertFalse(b.overlaps(a))

    def test_overlaps_identical(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.0.0.0/8')
        self.assertTrue(a.overlaps(b))

    def test_overlaps_cross_family(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv6Network('2001:db8::/32')
        with self.assertRaises(libcidr.FamilyError):
            a.overlaps(b)
        with self.assertRaises(libcidr.FamilyError):
            b.overlaps(a)

    def test_supernet_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        parent = net.supernet()
        self.assertIsInstance(parent, libcidr.IPv4Network)
        self.assertEqual(str(parent), '192.168.0.0/23')

    def test_supernet_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        parent = net.supernet()
        self.assertIsInstance(parent, libcidr.IPv6Network)
        self.assertEqual(str(parent), '2001:db8::/31')

    def test_supernet_chain_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        for expected_pfxlen in [23, 22, 21, 20]:
            net = net.supernet()
            self.assertEqual(net.prefixlen, expected_pfxlen)

    def test_supernet_overflow_v4(self):
        net = libcidr.IPv4Network('0.0.0.0/0')
        with self.assertRaises(libcidr.AddressOverflowError):
            net.supernet()

    def test_supernet_overflow_v6(self):
        net = libcidr.IPv6Network('::/0')
        with self.assertRaises(libcidr.AddressOverflowError):
            net.supernet()

    def test_subnets_v4(self):
        net = libcidr.IPv4Network('192.168.0.0/23')
        subnets = list(net.subnets(prefixlen=24))
        self.assertEqual(len(subnets), 2)
        self.assertEqual(str(subnets[0]), '192.168.0.0/24')
        self.assertEqual(str(subnets[1]), '192.168.1.0/24')

    def test_subnets_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        subnets = list(net.subnets(prefixlen=33))
        self.assertEqual(len(subnets), 2)
        self.assertEqual(str(subnets[0]), '2001:db8::/33')
        self.assertEqual(str(subnets[1]), '2001:db8:8000::/33')

    def test_subnets_single(self):
        net = libcidr.IPv4Network('192.168.1.0/31')
        subnets = list(net.subnets(prefixlen=32))
        self.assertEqual(len(subnets), 2)
        self.assertEqual(str(subnets[0]), '192.168.1.0/32')
        self.assertEqual(str(subnets[1]), '192.168.1.1/32')

    def test_subnets_type_is_network(self):
        net = libcidr.IPv4Network('10.0.0.0/24')
        for subnet in net.subnets(prefixlen=25):
            self.assertIsInstance(subnet, libcidr.IPv4Network)

    def test_contains_string_v4(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        self.assertTrue(net.contains('10.0.0.1'))
        self.assertFalse(net.contains('11.0.0.1'))

    def test_contains_address_object_v4(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        addr = libcidr.IPv4Address('10.0.0.1')
        self.assertTrue(net.contains(addr))

    def test_contains_string_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        self.assertTrue(net.contains('2001:db8::1'))
        self.assertFalse(net.contains('2001:db9::1'))

    def test_contains_cross_family(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        addr = libcidr.IPv6Address('::1')
        with self.assertRaises(libcidr.FamilyError):
            net.contains(addr)


class TestNetworkProtocol(unittest.TestCase):
    """Verify Python protocol methods for networks per ARCHITECTURE.md §8.7.4."""

    def test_str_equals_with_prefixlen(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        self.assertEqual(str(net), net.with_prefixlen)
        net6 = libcidr.IPv6Network('2001:db8::/32')
        self.assertEqual(str(net6), net6.with_prefixlen)

    def test_repr_ipv4(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        self.assertEqual(repr(net), "IPv4Network('192.168.1.0/24')")

    def test_repr_ipv6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        self.assertEqual(repr(net), "IPv6Network('2001:db8::/32')")

    def test_eq_equal(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.0.0.0/8')
        self.assertEqual(a, b)

    def test_eq_not_equal(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('192.168.0.0/16')
        self.assertNotEqual(a, b)

    def test_eq_cross_family(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv6Network('2001:db8::/32')
        with self.assertRaises(libcidr.FamilyError):
            a == b
        with self.assertRaises(libcidr.FamilyError):
            b == a

    def test_lt_ordering_v4(self):
        nets = [
            libcidr.IPv4Network('10.0.0.0/8'),
            libcidr.IPv4Network('10.0.0.0/16'),
            libcidr.IPv4Network('192.168.0.0/24'),
            libcidr.IPv4Network('172.16.0.0/12'),
        ]
        sorted_nets = sorted(nets)
        for i in range(len(sorted_nets) - 1):
            self.assertLessEqual(sorted_nets[i], sorted_nets[i + 1])
        # Verify the sort is by network address then prefix length.
        self.assertEqual(str(sorted_nets[0]), '10.0.0.0/8')
        self.assertEqual(str(sorted_nets[1]), '10.0.0.0/16')
        self.assertEqual(str(sorted_nets[2]), '172.16.0.0/12')
        self.assertEqual(str(sorted_nets[3]), '192.168.0.0/24')

    def test_lt_v4_network_asc_pfxlen_asc(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.0.0.0/16')
        self.assertLess(a, b)

    def test_lt_cross_family(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv6Network('2001:db8::/32')
        with self.assertRaises(libcidr.FamilyError):
            a < b
        with self.assertRaises(libcidr.FamilyError):
            b < a

    def test_hash_equal(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.0.0.0/8')
        self.assertEqual(hash(a), hash(b))

    def test_dict_key(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        d = {net: 'private'}
        self.assertEqual(
            d[libcidr.IPv4Network('10.0.0.0/8')], 'private')

    def test_set_member(self):
        a = libcidr.IPv4Network('10.0.0.0/8')
        b = libcidr.IPv4Network('10.0.0.0/8')
        s = {a, b}
        self.assertEqual(len(s), 1)

    def test_contains_protocol_v4(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        self.assertIn('10.0.0.1', net)
        self.assertNotIn('11.0.0.1', net)

    def test_contains_protocol_v6(self):
        net = libcidr.IPv6Network('2001:db8::/32')
        self.assertIn('2001:db8::1', net)
        self.assertNotIn('2001:db9::1', net)

    def test_contains_protocol_address_object(self):
        net = libcidr.IPv4Network('10.0.0.0/8')
        addr = libcidr.IPv4Address('10.0.0.1')
        self.assertIn(addr, net)


class TestNetworkEdgeCases(unittest.TestCase):
    """Verify edge-case network behavior."""

    def test_supernet_of_single_host_v4(self):
        net = libcidr.IPv4Network('192.168.1.0/32')
        self.assertEqual(str(net.supernet()), '192.168.1.0/31')

    def test_supernet_of_single_host_v6(self):
        net = libcidr.IPv6Network('2001:db8::1/128')
        self.assertEqual(str(net.supernet()), '2001:db8::/127')

    def test_zero_prefix_v4(self):
        net = libcidr.IPv4Network('0.0.0.0/0')
        self.assertEqual(net.prefixlen, 0)
        self.assertEqual(str(net.network_address), '0.0.0.0')

    def test_zero_prefix_v6(self):
        net = libcidr.IPv6Network('::/0')
        self.assertEqual(net.prefixlen, 0)
        self.assertEqual(str(net.network_address), '::')

    def test_max_prefix_v4(self):
        net = libcidr.IPv4Network('192.168.1.1/32')
        self.assertEqual(net.prefixlen, 32)
        first = net.network_address
        last = net.broadcast_address
        self.assertEqual(str(first), '192.168.1.1')
        self.assertEqual(str(last), '192.168.1.1')

    def test_max_prefix_v6(self):
        net = libcidr.IPv6Network('2001:db8::1/128')
        self.assertEqual(net.prefixlen, 128)
        self.assertEqual(str(net.network_address), '2001:db8::1')

    def test_ipv4_broadcast_address_24(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        self.assertEqual(str(net.broadcast_address), '192.168.1.255')

    def test_num_addresses_24(self):
        net = libcidr.IPv4Network('192.168.1.0/24')
        self.assertEqual(net.num_addresses, 256)

    def test_num_addresses_32(self):
        net = libcidr.IPv4Network('192.168.1.1/32')
        self.assertEqual(net.num_addresses, 1)

    def test_num_addresses_0(self):
        net = libcidr.IPv4Network('0.0.0.0/0')
        self.assertEqual(net.num_addresses, 2**32)

    def test_num_addresses_v6_128(self):
        net = libcidr.IPv6Network('::1/128')
        self.assertEqual(net.num_addresses, 1)

    def test_tuple_with_address_object(self):
        addr = libcidr.IPv4Address('192.168.1.5')
        net = libcidr.IPv4Network((addr, 24), strict=False)
        self.assertEqual(str(net), '192.168.1.0/24')

    def test_ipv4_network_repr_roundtrip(self):
        s = '10.0.0.0/8'
        net = libcidr.IPv4Network(s)
        restored = eval(repr(net), {'IPv4Network': libcidr.IPv4Network})
        self.assertEqual(restored, net)

    def test_ipv6_network_repr_roundtrip(self):
        s = '2001:db8::/32'
        net = libcidr.IPv6Network(s)
        restored = eval(repr(net), {'IPv6Network': libcidr.IPv6Network})
        self.assertEqual(restored, net)


if __name__ == '__main__':
    unittest.main()
