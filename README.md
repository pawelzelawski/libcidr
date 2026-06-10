# libcidr

libcidr is a C11 library and CPython extension for strict IPv4/IPv6 address
arithmetic, CIDR manipulation, bulk prefix operations, longest-prefix-match
indexing, and IANA special-purpose address classification. It does not do
routing protocol logic, network I/O, DNS resolution, or operational
routability inference beyond the documented classification flags.
Designed for Python users hitting pure-Python performance limits; see
bench/BASELINES.md for measured comparisons against ipaddress, netaddr, and
pytricia.

## Build Requirements

- libc
- Clang or GCC
- CPython 3.11 or newer for the Python binding

## Build And Install

### C Library

```sh
make
make install
```

This builds `libcidr.a` and installs:
- `libcidr.a` into `$(PREFIX)/lib`
- `libcidr.h` into `$(PREFIX)/include`

### Python Binding

If installing from PyPI:

```sh
pip install libcidr
```

If building from source:

```sh
make python-ext
make python-install
```

## Minimal C Example

```c
#include <stdio.h>

#include <libcidr.h>

int
main(void)
{
	cidr_addr_t addr;
	cidr_prefix_t prefix;
	cidr_class_t cls;
	bool contains;
	cidr_err_t rc;

	rc = cidr_addr_parse("192.168.1.10", &addr);
	if (rc != CIDR_OK)
		return 1;

	rc = cidr_addr_classify(&addr, &cls);
	if (rc != CIDR_OK)
		return 1;

	rc = cidr_prefix_parse("192.168.1.0/24", &prefix);
	if (rc != CIDR_OK)
		return 1;

	rc = cidr_prefix_contains(&prefix, &addr, &contains);
	if (rc != CIDR_OK)
		return 1;

	printf("private=%s contains=%s\n",
	       (cls & CIDR_CLASS_PRIVATE) ? "yes" : "no",
	       contains ? "yes" : "no");
	return 0;
}
```

Build example:

```sh
cc -std=c11 -I/usr/local/include example.c -L/usr/local/lib -lcidr -o example
./example
# output: private=yes contains=yes
```

## Minimal Python Example

```python
import libcidr

addrs = [
    libcidr.IPv4Address("10.1.2.3"),
    libcidr.IPv4Address("203.0.113.10"),
]
prefixes = [
    libcidr.IPv4Network("10.0.0.0/8"),
    libcidr.IPv4Network("192.168.0.0/16"),
]

print(libcidr.bulk_contains(addrs, prefixes))
# [0, -1]
```

## Known Limitations

- No network I/O
- No DNS resolution
- `CIDR_CLASS_GLOBAL` means no special-purpose block matched; it does not
  imply real-world routability

## Design Rationale

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design rationale and
internal specification.

## License

ISC License. See [LICENSE](LICENSE).
