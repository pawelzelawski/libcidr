# Tech Stack

## 1. Language

### C (C11)

libcidr is written in C11. No C++, no scripting languages, no code generation.

**Standard**: C11 (`-std=c11`)

**Why C11 over C99**:
- `_Static_assert` for compile-time enforcement of struct sizes and layout
  invariants: `sizeof(cidr_addr_t) == 20`, `sizeof(cidr_prefix_t) == 24`,
  and alignment properties required for correct array layout
- `_Bool` / `<stdbool.h>` for the `bool *out` parameters used in
  `cidr_prefix_contains()` and `cidr_prefix_overlaps()`
- Anonymous unions in `cidr_addr_t` for the `addr.v4` / `addr.v6` union
  that gives direct named access to IPv4 and IPv6 bytes
- Designated initialisers for the classification table and test fixtures

**Feature test macros** (defined in Makefile, not in source files):
```c
_POSIX_C_SOURCE=200809L   /* required for ssize_t on Linux */
```

`ssize_t` is used in `cidr_bulk_contains()` and `cidr_index_lookup()` for
the match index output array. It is POSIX, not C11 standard. The feature
test macro must be defined before any system header is included; defining it
in the Makefile rather than in source files avoids order-of-include
dependencies. OpenBSD provides `ssize_t` without this macro, but defining it
is harmless on all targets.

Do not define `_GNU_SOURCE` -- it pulls in non-portable extensions and breaks
OpenBSD builds.

---

## 2. External Dependencies

libcidr has **zero external library dependencies**. This is a hard
requirement, not a preference.

The only dependencies are the C standard library and the POSIX interfaces
listed in §3. There are no vendored libraries, no submodules, and no package
manager files.

The Python extension adds CPython as a build-time dependency, but not a
runtime dependency for the C library. The C library builds and links
without Python present.

**Runtime dependencies for C callers**:
- Linux: none beyond libc
- OpenBSD: none beyond libc

**Runtime dependencies for Python callers**:
- CPython 3.11 or later (stable ABI; `.so` loads on any 3.x ≥ 3.11)

---

## 3. System Libraries

These are part of the C standard library or POSIX and require no installation.

### 3.1 Standard C Library

```c
#include <stddef.h>     /* size_t, NULL, offsetof */
#include <stdint.h>     /* uint8_t, uint32_t, uint64_t, size_t */
#include <stdbool.h>    /* bool, true, false */
#include <string.h>     /* memcmp, memset, memcpy */
#include <stdlib.h>     /* malloc, free -- cidr_index_create/destroy only */
```

`<stdlib.h>` is included only by `src/cidr_index.c`. Every other translation
unit is allocation-free at runtime. No other translation unit may include
`<stdlib.h>` -- an unintended `malloc` or `free` call in any bulk or
arithmetic path is a violation of the zero-allocation model.

### 3.2 POSIX

```c
#include <sys/types.h>  /* ssize_t */
```

`ssize_t` is required for the match index arrays in `cidr_bulk_contains()`
and `cidr_index_lookup()`. It is the only POSIX type used in the public API.
On Linux, `<sys/types.h>` or `<unistd.h>` provides it under
`_POSIX_C_SOURCE=200809L`. On OpenBSD, it is available without the macro.

### 3.3 Test-Only Libraries

Test binaries include:
```c
#include <stdio.h>      /* fprintf, printf -- test output only */
#include <assert.h>     /* assert -- debug builds and test assertions */
```

These headers are never included in `src/` or `python/`. Test-only includes
belong only in `tests/`.

### 3.4 Python Extension

The Python extension builds against the CPython stable ABI:
```c
#define Py_LIMITED_API 0x030B0000   /* CPython 3.11 stable ABI floor */
#include <Python.h>
```

The stable ABI guarantees binary compatibility across CPython 3.11 and all
future 3.x releases without recompilation. `Python.h` implicitly includes the
required C standard headers; the extension source file does not include
`<stdint.h>` or `<stdbool.h>` separately.

---

## 4. Build System

### 4.1 Makefile Structure

One top-level Makefile. No per-directory Makefiles. Platform and architecture
detected at build time.

```
libcidr/
├── Makefile
├── include/
│   └── libcidr.h       ← public header
├── src/
│   └── *.c             ← C library source files
├── python/
│   └── _libcidr_ext.c  ← CPython binding layer
├── tests/
│   └── *.c / *.py      ← tests
└── bench/
    └── *.c / *.py      ← benchmarks
```

The primary output of `make` is a static archive (`libcidr.a`). A shared
library target (`libcidr.so`) is also provided. The Python extension is a
separate target (`libcidr.so` in the Python module sense -- see §5).

Embedders link against `libcidr.a` and include `include/libcidr.h`. Nothing
else is needed.

### 4.2 Compiler

**Primary**: Clang (preferred on both platforms).

OpenBSD ships Clang as the system compiler. On Linux:
```sh
# Debian/Ubuntu
apt install clang

# RHEL/Fedora
dnf install clang

# Arch
pacman -S clang
```

Minimum supported version: Clang 11.0. Required for full C11 `_Static_assert`
support and `-fsanitize=address,undefined`.

GCC is a supported secondary compiler for the C library. GCC does not support
the TSan inter-thread annotation APIs at the level Clang does; the
`make test-tsan` target requires Clang. All other targets build cleanly with
either compiler.

### 4.3 Compiler Flags

```makefile
# Platform detection
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
    CFLAGS_OS   = -DCIDR_LINUX
    LDFLAGS     =
endif
ifeq ($(UNAME), OpenBSD)
    CFLAGS_OS   = -DCIDR_OPENBSD
    LDFLAGS     =
endif

# Architecture detection
ARCH := $(shell uname -m)

# Common flags -- all builds
CFLAGS_BASE = -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer

# Feature test macros -- defined here, not in source
CFLAGS_FT   = -D_POSIX_C_SOURCE=200809L

# Development build -- ASan + UBSan + debug assertions
CFLAGS_DEV  = $(CFLAGS_BASE) $(CFLAGS_FT) $(CFLAGS_OS) \
              -O1 -g \
              -fsanitize=address,undefined

# Release build
CFLAGS_REL  = $(CFLAGS_BASE) $(CFLAGS_FT) $(CFLAGS_OS) \
              -O2 -DNDEBUG

# TSan build -- mutually exclusive with ASan
CFLAGS_TSAN = $(CFLAGS_BASE) $(CFLAGS_FT) $(CFLAGS_OS) \
              -O1 -g \
              -fsanitize=thread
```

`-fno-omit-frame-pointer` is required in all builds. Frame pointers are
essential for accurate Valgrind stack traces, perf profiling on bulk
operations, and backtraces in crash reports. This flag is never relaxed.

`-Werror` is required. Warnings that are not fixed are bugs.

**`CIDR_LINUX` and `CIDR_OPENBSD`**: These macros are defined for completeness
and for use in tests. The C library itself has no platform-specific code --
it uses only portable C11 and POSIX. The macros exist so that test files can
conditionally compile platform-specific test cases without using `__linux__`
or `__OpenBSD__` directly, keeping preprocessor usage consistent across the
codebase.

### 4.4 Build Targets

```makefile
make              # same as make release -- builds libcidr.a
make dev          # debug build with ASan/UBSan
make release      # optimised build -- libcidr.a
make shared       # shared C library -- libcidr.so
make test         # build and run C tests (dev flags)
make test-python  # run Python binding tests (requires python-ext built)
make test-tsan    # build and run C tests under ThreadSanitizer (Clang only)
make valgrind     # run C tests under Valgrind (Linux only)
make bench        # build and run C benchmarks (release flags)
make bench-python # run Python benchmarks (release flags)
make python-ext   # build Python extension (see §5)
make python-install # install Python extension to site-packages
make lint         # clang-tidy + cppcheck on src/ and python/
make format       # clang-format on src/*.c src/*.h include/libcidr.h
make clean        # remove all build artifacts
make install      # install libcidr.a and include/libcidr.h to PREFIX
```

`make install` installs exactly two files: `libcidr.a` into `$(LIBDIR)`
(default `$(PREFIX)/lib`) and `libcidr.h` into `$(INCLUDEDIR)` (default
`$(PREFIX)/include`). The Python extension is installed separately via
`make python-install`.

---

## 5. Python Extension Build

### 5.1 Build Approach

The Python extension (`_libcidr_ext.c`) is compiled against CPython's stable
ABI using `python3-config` to obtain the correct include paths and linker
flags. This keeps the extension build inside the Makefile without requiring
setuptools, pip, or any Python packaging infrastructure as a build-time
dependency.

```makefile
PY        := python3
PYCONFIG  := python3-config
PYINC     := $(shell $(PYCONFIG) --includes)
PYLDFLAGS := $(shell $(PYCONFIG) --ldflags --embed)
PYSUFFIX  := $(shell $(PY) -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))")

# The extension module must be named libcidr<EXT_SUFFIX>
# EXT_SUFFIX encodes the stable ABI marker and platform tag:
# libcidr.cpython-311-x86_64-linux-gnu.so  (CPython-version-specific build)
# libcidr.abi3.so                           (stable ABI build, loads on 3.11+)
#
# With Py_LIMITED_API the suffix is .abi3.so on Linux and .abi3.so on OpenBSD.
PYEXT     := libcidr$(PYSUFFIX)

CFLAGS_PYEXT = -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer \
               -O2 -DNDEBUG -fPIC \
               -DPy_LIMITED_API=0x030B0000 \
               $(PYINC) \
               -I include/

python-ext: libcidr.a python/$(PYEXT)

python/_libcidr_ext.o: python/_libcidr_ext.c include/libcidr.h
	$(CC) $(CFLAGS_PYEXT) -c $< -o $@

python/$(PYEXT): python/_libcidr_ext.o libcidr.a
	$(CC) -shared $(PYLDFLAGS) $^ -o $@
```

The extension links against `libcidr.a` statically. The resulting `.so`
contains the arithmetic, bulk, and classification logic and has no runtime
dependency on a separate `libcidr.so`. This simplifies deployment -- Python
users install one file.

### 5.2 Stable ABI

`-DPy_LIMITED_API=0x030B0000` restricts the extension to the CPython 3.11
stable ABI. The resulting `.abi3.so` loads on CPython 3.11, 3.12, 3.13, and
any future 3.x release without recompilation. The Makefile verifies the
resulting suffix contains `abi3`:

```makefile
python-check-abi:
	@echo "Extension suffix: $(PYSUFFIX)"
	@echo "$(PYSUFFIX)" | grep -q "abi3" || \
	    (echo "ERROR: extension was not built against stable ABI"; exit 1)
```

If the suffix does not contain `abi3`, the build is using the full CPython
API and the `.so` is tied to a specific minor version. This check catches
accidentally dropped `-DPy_LIMITED_API` defines.

### 5.3 Python Extension Build Targets

```makefile
make python-ext      # compile _libcidr_ext.c against libcidr.a -> python/libcidr.abi3.so
make python-install  # copy python/libcidr.abi3.so to $(PY) site-packages
                     # or use: pip install . (see §5.4)
make python-dev      # build with ASan/UBSan -- for test runs under sanitizers
make test-python     # run tests/test_python.py against the built extension
make bench-python    # run bench/bench_python.py against the built extension
```

### 5.4 Distribution (pyproject.toml)

For distribution via PyPI or local `pip install`, a minimal `pyproject.toml`
is provided. It uses `setuptools` as the build backend with a thin
`setup.py` that delegates to `Makefile`:

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "libcidr"
version = "1.0.0"
requires-python = ">=3.11"
description = "IPv4/IPv6 address arithmetic and CIDR manipulation"
license = {text = "ISC"}
```

The `pyproject.toml` is used only for distribution. The Makefile is the
authoritative build system for development. Running `pip install .` in the
repository root builds and installs the extension using the Makefile targets
internally.

---

## 6. Test Harness

### 6.1 Structure

C tests are written using a minimal test harness defined in
`tests/test_harness.h`. No third-party test framework is used.

```c
/* tests/test_harness.h */
#define RUN(name, fn) do {                                           \
    tests_run++;                                                     \
    int _rc = (fn)();                                                \
    if (_rc == 0) {                                                  \
        tests_passed++;                                              \
        fprintf(stderr, "PASS: %s\n", (name));                      \
    } else {                                                         \
        fprintf(stderr, "FAIL: %s\n", (name));                      \
    }                                                                \
} while (0)

extern int tests_run;
extern int tests_passed;
```

Each test function returns 0 on success and non-zero on failure. The test
binary exits with code 0 if all tests pass and 1 if any fail.

```sh
make test
# output:
# PASS: test_ipv4_parse_valid
# PASS: test_ipv4_parse_leading_zero_rejected
# ...
# 142/142 tests passed
```

### 6.2 Test Binary Structure

```
tests/
├── test_harness.h      ← RUN macro, tests_run / tests_passed counters
├── run_tests.c         ← binary entry point -- calls RUN() for every suite
├── test_addr.c         ← cidr_addr_parse, cidr_addr_format, cidr_addr_to_v4,
│                           cidr_addr_cmp
├── test_prefix.c       ← cidr_prefix_* arithmetic, subnet iterator,
│                           cidr_prefix_cmp
├── test_bulk.c         ← cidr_bulk_parse, cidr_bulk_contains,
│                           cidr_bulk_aggregate, cidr_bulk_sort
├── test_classify.c     ← cidr_addr_classify against full IANA table
└── test_index.c        ← Patricia trie correctness
```

`make test` links all `.c` test files against `libcidr.a`. Tests exercise
the exported public API only -- no test links directly against internal
object files or includes internal headers.

### 6.3 Python Test Structure

Python tests use `unittest`. No third-party Python test framework is used.

```sh
make test-python
# equivalent to:
python3 -m pytest tests/test_python.py -v
# or without pytest:
python3 -m unittest tests/test_python -v
```

The `test_python.py` test file imports `libcidr` from the built
`python/libcidr.abi3.so`. The Makefile prepends the `python/` directory to
`PYTHONPATH` so the extension is found without installation.

Python tests compare results against `ipaddress` stdlib for all operations
where `ipaddress` is the correctness reference. See TESTING.md §2 for the
full test catalogue.

---

## 7. Development Tools

### 7.1 Valgrind (Linux only)

**Purpose**: Memory error detection -- leaks, use-after-free, uninitialised
reads.

**Installation**: `apt install valgrind`

**Usage**:
```sh
make valgrind
# equivalent to:
valgrind --leak-check=full          \
         --show-leak-kinds=all      \
         --track-origins=yes        \
         --error-exitcode=1         \
         ./tests/run_tests
```

libcidr's C library is allocation-free except in `cidr_index_create()`. All
tests that create a `cidr_index_t` must call `cidr_index_destroy()` on all
paths including error paths. Valgrind will catch any failure to release index
memory.

No suppression file is needed. libcidr has no external library dependencies
that would require suppressions.

All C tests must pass Valgrind clean. Run on Linux before every commit.
Valgrind is not available on OpenBSD -- use the ASan build there.

### 7.2 AddressSanitizer and UndefinedBehaviorSanitizer

**Purpose**: Runtime memory and undefined behaviour detection.

**Compiler flags**: `-fsanitize=address,undefined` when supported by the
active toolchain; `make dev` enables them automatically when available.

Available on Linux with Clang. On OpenBSD, sanitizer availability depends on
the installed Clang toolchain; the base system compiler may not ship ASan/UBSan
runtimes.

```sh
make dev    # compiles with -fsanitize=address,undefined when supported
make test
```

UBSan catches integer overflows, null pointer dereferences, misaligned
accesses, and out-of-bounds array indexing. Every bulk operation that
accepts caller-provided arrays must be verified under UBSan -- the caller-
provided buffer model requires that the library never accesses outside the
declared bounds.

All C tests must pass ASan/UBSan clean on every target whose toolchain
supports those sanitizers.

**Python extension under ASan**: The Python extension can be tested under ASan
by building it with ASan flags and running the Python test suite with the
appropriate `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES` setting. The `make python-dev`
target builds the extension with ASan flags for this purpose.

### 7.3 ThreadSanitizer

**Purpose**: Data race detection.

TSan and ASan are mutually exclusive -- TSan runs as a separate target.

```sh
make test-tsan
# equivalent to:
# rebuild with -fsanitize=thread and run the test binary
```

libcidr's C library is fully thread-safe for non-index operations (no shared
mutable state) and safe for concurrent `cidr_index_lookup()` calls on a
completed index. TSan verifies that no data races exist in the bulk and
classification paths when used from multiple threads simultaneously.

TSan is not a per-commit gate. Run at phase boundaries and before release.

**TSan availability**: Clang only for the full TSan fiber-aware APIs. The
standard `-fsanitize=thread` mode works with GCC for basic race detection, but
Clang is required for accurate results.

### 7.4 clang-tidy

**Purpose**: Static analysis.

**Installation**: `apt install clang-tidy` (Linux) -- included with Clang on
OpenBSD.

**Configuration**: `.clang-tidy` in repository root.

```sh
make lint
# or directly:
clang-tidy src/*.c python/_libcidr_ext.c -- $(CFLAGS_DEV) -I include/
```

Both the C library source and the Python extension source are linted. The
Python extension is included because it contains non-trivial C code with
reference counting requirements.

### 7.5 cppcheck

**Purpose**: Additional static analysis, complementary to clang-tidy.

**Installation**: `apt install cppcheck` / `pkg_add cppcheck`

```sh
cppcheck --enable=all --error-exitcode=1 \
         --suppress=missingIncludeSystem \
         src/ python/
```

### 7.6 clang-format

**Purpose**: Consistent code formatting.

**Configuration**: `.clang-format` in repository root. KNF-based style.

```sh
make format
# equivalent to:
clang-format -i src/*.c src/*.h include/libcidr.h python/_libcidr_ext.c
```

CI rejects commits that are not clang-format clean. The Python extension
source is included -- it follows the same KNF formatting as the C library
source.

### 7.7 GitHub Actions CI

CI runs on every push and pull request. The matrix covers all four targets:

```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest
        arch: x86_64
      - os: ubuntu-latest-arm64
        arch: arm64
      - os: openbsd-latest
        arch: amd64
      - os: openbsd-latest-arm64
        arch: arm64

steps:
  - run: make dev
  - run: make test
  - run: make valgrind     # Linux only
  - run: make test-tsan    # Linux only, Clang only
  - run: make lint
```

Python tests run against a matrix of CPython versions:

```yaml
python-version: ["3.11", "3.12", "3.13"]
steps:
  - run: make python-ext
  - run: make test-python
```

---

## 8. Dependency Summary

| Dependency | Version | Type | Purpose | Platforms |
|---|---|---|---|---|
| Clang | ≥ 11.0 | Build tool | Compilation, ASan/UBSan, TSan | Linux, OpenBSD |
| GCC | ≥ 10.0 | Build tool | Secondary compiler (no TSan) | Linux |
| libc | system | System lib | Standard C (stddef, stdint, stdbool, string, stdlib) | Linux, OpenBSD |
| CPython | ≥ 3.11 | Build tool | Python extension compilation | Linux, OpenBSD |
| Valgrind | latest | Dev tool | Memory checking | Linux only |
| clang-tidy | ≥ 11.0 | Dev tool | Static analysis | Linux, OpenBSD |
| cppcheck | latest | Dev tool | Static analysis | Linux, OpenBSD |

**Runtime dependencies for C callers**:
- Linux: libc only
- OpenBSD: libc only

**Runtime dependencies for Python callers**:
- CPython 3.11 or later (stable ABI binary)

**Development-only dependencies** (not required to use the library):
- Valgrind (Linux only)
- clang-tidy, cppcheck
- CPython (required only to build and test the Python extension)

---

**See Also**: PROJECT.md, ARCHITECTURE.md, CODING_STANDARDS.md, DEVELOPMENT.md
