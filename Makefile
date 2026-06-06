# Makefile - libcidr
#
# Targets:
#   make / make dev    - debug build, enables ASan/UBSan when supported, runs tests
#   make release       - optimised static library
#   make test          - build and run test suite (dev flags)
#   make test-tsan     - TSan build and test run, Clang only, Linux only
#   make valgrind      - run tests under Valgrind, Linux only
#   make lint          - clang-tidy + cppcheck
#   make format        - clang-format -i on all sources
#   make clean         - remove build artefacts
#   make install       - install libcidr.a and include/libcidr.h
#   make python-ext    - build CPython extension
#   make python-check-abi - verify stable ABI marker
#   make python-dev    - build CPython extension with ASan/UBSan when supported
#   make test-python   - run Python binding tests
#
# Compatible with GNU make (Linux) and BSD make (OpenBSD).
# Uses != for shell assignment - supported by both.
# Explicit per-file compile rules - no pattern rules (BSD make portable).
# See TECH_STACK.md §4 for full build system specification.

# --- Platform detection -- != is portable to GNU make >= 3.82 and BSD make ---

OS   != uname -s
ARCH != uname -m

# --- Compiler ----------------------------------------------------------------

# Clang primary (required for TSan), GCC secondary.
# Override: make CC=gcc
CC = clang
AR = ar

# --- Compiler flags ----------------------------------------------------------

CFLAGS_COMMON = -std=c11 -Wall -Wextra -Wpedantic -Werror	\
                -Wno-unused-parameter				\
                -fno-omit-frame-pointer				\
                -D_POSIX_C_SOURCE=200809L			\
                -D_XOPEN_SOURCE=700

# Platform flags
CFLAGS_OS != if [ "$(OS)" = "Linux" ]; then echo "-DCIDR_LINUX"; \
              elif [ "$(OS)" = "OpenBSD" ]; then echo "-DCIDR_OPENBSD"; \
              else echo ""; fi

# ASan/UBSan - enable only when the active compiler supports the flags.
# OpenBSD base clang may not ship sanitizer runtimes.
SANITIZERS != if printf 'int main(void){return 0;}\n' | \
                  $(CC) -x c -std=c11 -fsyntax-only \
                  -fsanitize=address,undefined - >/dev/null 2>&1; then \
                  echo "-fsanitize=address,undefined"; \
              else \
                  echo ""; \
              fi

CFLAGS_DEV     = $(CFLAGS_COMMON) $(CFLAGS_OS)			\
	                 -O1 -g						\
	                 $(SANITIZERS)					\
	                 -DCIDR_STACK_CHECK				\
	                 -DCIDR_TEST

CFLAGS_RELEASE = $(CFLAGS_COMMON) $(CFLAGS_OS) -O2 -DNDEBUG

CFLAGS_TSAN    = $(CFLAGS_COMMON) $(CFLAGS_OS)			\
                 -O1 -g					\
                 -fsanitize=thread				\
                 -fno-omit-frame-pointer				\
                 -DCIDR_TEST

CFLAGS_VG      = $(CFLAGS_COMMON) $(CFLAGS_OS)			\
                 -O1 -g					\
                 -DCIDR_TEST

# --- Source files -------------------------------------------------------------

LIB_SRCS = src/cidr_addr.c					\
           src/cidr_prefix.c				\
           src/cidr_bulk.c					\
           src/cidr_classify.c				\
           src/cidr_index.c

TEST_SRCS = tests/run_tests.c tests/test_addr.c tests/test_prefix.c \
            tests/test_bulk.c tests/test_classify.c
TEST_SRCS_TSAN = $(TEST_SRCS) tests/test_tsan.c

THREAD_FLAGS = -pthread

# --- Build paths --------------------------------------------------------------

BUILD_DIR       = build
REL_DIR         = $(BUILD_DIR)/rel
TSAN_DIR        = $(BUILD_DIR)/tsan
VG_DIR          = $(BUILD_DIR)/vg
BUILD_TESTS_DIR = $(BUILD_DIR)/tests
PY_DIR          = python

LIB_DEV     = $(BUILD_DIR)/libcidr.a
LIB_RELEASE = $(REL_DIR)/libcidr.a
LIB_TSAN    = $(TSAN_DIR)/libcidr.a
LIB_VG      = $(VG_DIR)/libcidr.a

TEST_BIN      = $(BUILD_TESTS_DIR)/run_tests
TEST_BIN_TSAN = $(BUILD_TESTS_DIR)/run_tests_tsan
TEST_BIN_VG   = $(BUILD_TESTS_DIR)/run_tests_vg

INCLUDES = -I include/

# --- Python extension ---------------------------------------------------------
#
# Stable ABI: the extension is compiled with Py_LIMITED_API = 0x030B0000
# and the output filename uses the .abi3.so suffix. The extension does NOT
# link against libpython; Python symbols are resolved at load time by the
# interpreter. See TECH_STACK.md §5.1 for the build approach.

PY        != command -v python3 2>/dev/null || echo python3
PYCONFIG  != command -v python3-config 2>/dev/null || echo python3-config
PYINC     != $(PYCONFIG) --includes 2>/dev/null || echo ""
PYINC_TIDY != $(PYCONFIG) --includes 2>/dev/null | sed 's/-I/-isystem /g'

# Stable ABI extension: .abi3.so suffix, no version-specific tag.
PYEXT_ABI3 = libcidr.abi3.so

CFLAGS_PYEXT = -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer	\
               -O2 -DNDEBUG -fPIC					\
               -DPy_LIMITED_API=0x030B0000				\
               $(PYINC)							\
               -I include/

# --- Install paths ------------------------------------------------------------

PREFIX     ?= /usr/local
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

# --- Phony targets ------------------------------------------------------------

.PHONY: all dev release shared test test-tsan valgrind lint format clean	\
        install python-ext python-check-abi python-install python-dev	\
        test-python bench bench-python

all: release

# --- dev: debug build + run tests ---------------------------------------------

dev: $(TEST_BIN)
	$(TEST_BIN)

# --- release: optimised static library -----------------------------------------

release: $(LIB_RELEASE)

# --- shared: shared C library (stub) ------------------------------------------

shared:
	@echo "shared library not yet implemented (Phase 1 stub)"

# --- test: same as dev (alias) ------------------------------------------------

test: $(TEST_BIN)
	$(TEST_BIN)

# --- test-tsan: TSan build, Clang only, Linux only ----------------------------

test-tsan:
	@command -v clang >/dev/null 2>&1 || \
	    { echo "test-tsan: TSan requires Clang"; exit 1; }
	@if [ "$(OS)" != "Linux" ]; then \
	    echo "test-tsan: Linux only (OpenBSD clang has no TSan runtime)"; \
	    exit 1; \
	fi
	@mkdir -p $(TSAN_DIR) $(BUILD_TESTS_DIR)
	$(CC) $(CFLAGS_TSAN) $(THREAD_FLAGS) $(INCLUDES) -c src/cidr_addr.c     -o $(TSAN_DIR)/cidr_addr.o
	$(CC) $(CFLAGS_TSAN) $(THREAD_FLAGS) $(INCLUDES) -c src/cidr_prefix.c   -o $(TSAN_DIR)/cidr_prefix.o
	$(CC) $(CFLAGS_TSAN) $(THREAD_FLAGS) $(INCLUDES) -c src/cidr_bulk.c     -o $(TSAN_DIR)/cidr_bulk.o
	$(CC) $(CFLAGS_TSAN) $(THREAD_FLAGS) $(INCLUDES) -c src/cidr_classify.c  -o $(TSAN_DIR)/cidr_classify.o
	$(CC) $(CFLAGS_TSAN) $(THREAD_FLAGS) $(INCLUDES) -c src/cidr_index.c     -o $(TSAN_DIR)/cidr_index.o
	ar rcs $(LIB_TSAN)						\
	    $(TSAN_DIR)/cidr_addr.o					\
	    $(TSAN_DIR)/cidr_prefix.o					\
	    $(TSAN_DIR)/cidr_bulk.o					\
	    $(TSAN_DIR)/cidr_classify.o				\
	    $(TSAN_DIR)/cidr_index.o
	$(CC) $(CFLAGS_TSAN) -DCIDR_TSAN $(THREAD_FLAGS) $(INCLUDES) -I tests/	\
	    $(TEST_SRCS_TSAN) $(LIB_TSAN)			\
	    -o $(TEST_BIN_TSAN)
	$(TEST_BIN_TSAN)

# --- valgrind: Linux only, no sanitizers (ASan + Valgrind conflict) -----------

valgrind: $(TEST_BIN_VG)
	@if [ "$(OS)" != "Linux" ]; then \
	    echo "valgrind: Linux only"; exit 1; \
	fi
	valgrind --leak-check=full					\
	         --show-leak-kinds=all				\
	         --track-origins=yes					\
	         --error-exitcode=1					\
	         $(TEST_BIN_VG)

# --- Python extension ----------------------------------------------------------

python-ext: $(PY_DIR)/$(PYEXT_ABI3)

$(PY_DIR)/_libcidr_ext.o: $(PY_DIR)/_libcidr_ext.c include/libcidr.h
	$(CC) $(CFLAGS_PYEXT) -c $< -o $@

$(PY_DIR)/$(PYEXT_ABI3): $(PY_DIR)/_libcidr_ext.o $(LIB_RELEASE)
	$(CC) -shared $^ -o $@

python-check-abi:
	@echo "Extension filename: $(PYEXT_ABI3)"
	@echo "$(PYEXT_ABI3)" | grep -q "abi3" || \
	    (echo "ERROR: extension was not built against stable ABI"; exit 1)

python-install: $(PY_DIR)/$(PYEXT_ABI3)
	@PYSITE=$$($(PY) -c "import site; print(site.getsitepackages()[0])"); \
	    echo "Installing to $${PYSITE}/$(PYEXT_ABI3)"; \
	    install -d $(DESTDIR)$${PYSITE}; \
	    install -m 644 $(PY_DIR)/$(PYEXT_ABI3) $(DESTDIR)$${PYSITE}/$(PYEXT_ABI3)

python-dev:
	@mkdir -p $(BUILD_DIR)/pydev
	$(CC) -std=c11 -Wall -Wextra -Werror -fno-omit-frame-pointer	\
	      -O1 -g -fPIC						\
	      -DPy_LIMITED_API=0x030B0000				\
	      $(SANITIZERS)						\
	      $(PYINC)							\
	      -I include/						\
	      -c $(PY_DIR)/_libcidr_ext.c				\
	      -o $(BUILD_DIR)/pydev/_libcidr_ext.o
	$(CC) -shared							\
	      $(BUILD_DIR)/pydev/_libcidr_ext.o $(LIB_DEV)		\
	      -o $(PY_DIR)/$(PYEXT_ABI3)

test-python: $(PY_DIR)/$(PYEXT_ABI3)
	PYTHONPATH=$(PY_DIR) $(PY) -m unittest tests.test_python -v

# --- Benchmarks (Phase 8) -----------------------------------------------------
# Built under release flags. Stubs until implemented.

bench:
	@echo "C benchmarks not yet implemented (Phase 8)"

bench-python:
	@echo "Python benchmarks not yet implemented (Phase 8)"

# --- lint: clang-tidy + cppcheck -----------------------------------------------

lint:
	clang-tidy --quiet $(LIB_SRCS) python/_libcidr_ext.c	\
	    -- $(CFLAGS_DEV) $(INCLUDES) $(PYINC_TIDY)
	@if command -v cppcheck >/dev/null 2>&1; then \
	    cppcheck --enable=all --error-exitcode=1		\
	             --suppress=missingIncludeSystem		\
	             --suppress=unusedFunction			\
	             --suppress=checkersReport			\
	             --suppress=staticFunction			\
	             --suppress=unmatchedSuppression		\
	             --check-level=exhaustive			\
	             src/ python/;				\
	else \
	    echo "cppcheck not found; skipping"; \
	fi

# --- format --------------------------------------------------------------------

format:
	clang-format -i							\
	    src/cidr_addr.c						\
	    src/cidr_prefix.c						\
	    src/cidr_bulk.c						\
	    src/cidr_classify.c					\
	    src/cidr_index.c						\
	    src/cidr_internal.h					\
	    include/libcidr.h						\
	    python/_libcidr_ext.c					\
	    tests/run_tests.c						\
	    tests/test_addr.c						\
	    tests/test_prefix.c						\
	    tests/test_bulk.c						\
	    tests/test_harness.h

# --- install -------------------------------------------------------------------

install: $(LIB_RELEASE)
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	install -m 644 $(LIB_RELEASE) $(DESTDIR)$(LIBDIR)/libcidr.a
	install -m 644 include/libcidr.h $(DESTDIR)$(INCLUDEDIR)/libcidr.h

# --- clean ---------------------------------------------------------------------

clean:
	rm -rf $(BUILD_DIR)

# --- Development library (explicit per-file compile + ar) ----------------------

$(LIB_DEV): $(LIB_SRCS) include/libcidr.h src/cidr_internal.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -c src/cidr_addr.c     -o $(BUILD_DIR)/cidr_addr.o
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -c src/cidr_prefix.c   -o $(BUILD_DIR)/cidr_prefix.o
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -c src/cidr_bulk.c     -o $(BUILD_DIR)/cidr_bulk.o
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -c src/cidr_classify.c  -o $(BUILD_DIR)/cidr_classify.o
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -c src/cidr_index.c     -o $(BUILD_DIR)/cidr_index.o
	ar rcs $(LIB_DEV)						\
	    $(BUILD_DIR)/cidr_addr.o					\
	    $(BUILD_DIR)/cidr_prefix.o				\
	    $(BUILD_DIR)/cidr_bulk.o					\
	    $(BUILD_DIR)/cidr_classify.o				\
	    $(BUILD_DIR)/cidr_index.o

# --- Release library (explicit per-file compile + ar) -------------------------

$(LIB_RELEASE): $(LIB_SRCS) include/libcidr.h src/cidr_internal.h
	@mkdir -p $(REL_DIR)
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) -c src/cidr_addr.c     -o $(REL_DIR)/cidr_addr.o
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) -c src/cidr_prefix.c   -o $(REL_DIR)/cidr_prefix.o
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) -c src/cidr_bulk.c     -o $(REL_DIR)/cidr_bulk.o
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) -c src/cidr_classify.c  -o $(REL_DIR)/cidr_classify.o
	$(CC) $(CFLAGS_RELEASE) $(INCLUDES) -c src/cidr_index.c     -o $(REL_DIR)/cidr_index.o
	ar rcs $(LIB_RELEASE)						\
	    $(REL_DIR)/cidr_addr.o					\
	    $(REL_DIR)/cidr_prefix.o					\
	    $(REL_DIR)/cidr_bulk.o					\
	    $(REL_DIR)/cidr_classify.o					\
	    $(REL_DIR)/cidr_index.o

# --- Valgrind library (no sanitizers) ------------------------------------------

$(LIB_VG): $(LIB_SRCS) include/libcidr.h src/cidr_internal.h
	@mkdir -p $(VG_DIR)
	$(CC) $(CFLAGS_VG) $(INCLUDES) -c src/cidr_addr.c     -o $(VG_DIR)/cidr_addr.o
	$(CC) $(CFLAGS_VG) $(INCLUDES) -c src/cidr_prefix.c   -o $(VG_DIR)/cidr_prefix.o
	$(CC) $(CFLAGS_VG) $(INCLUDES) -c src/cidr_bulk.c     -o $(VG_DIR)/cidr_bulk.o
	$(CC) $(CFLAGS_VG) $(INCLUDES) -c src/cidr_classify.c  -o $(VG_DIR)/cidr_classify.o
	$(CC) $(CFLAGS_VG) $(INCLUDES) -c src/cidr_index.c     -o $(VG_DIR)/cidr_index.o
	ar rcs $(LIB_VG)						\
	    $(VG_DIR)/cidr_addr.o					\
	    $(VG_DIR)/cidr_prefix.o					\
	    $(VG_DIR)/cidr_bulk.o					\
	    $(VG_DIR)/cidr_classify.o					\
	    $(VG_DIR)/cidr_index.o

# --- Test binary (dev build / ASan) -------------------------------------------
# Compile+link in one shot -- no separate test object files.

$(TEST_BIN): $(LIB_DEV) $(TEST_SRCS) include/libcidr.h tests/test_harness.h
	@mkdir -p $(BUILD_TESTS_DIR)
	$(CC) $(CFLAGS_DEV) $(INCLUDES) -I tests/	\
	    $(TEST_SRCS) $(LIB_DEV)			\
	    -o $(TEST_BIN)

# --- Valgrind test binary (no sanitizers) ------------------------------------

$(TEST_BIN_VG): $(LIB_VG) $(TEST_SRCS) include/libcidr.h tests/test_harness.h
	@mkdir -p $(BUILD_TESTS_DIR)
	$(CC) $(CFLAGS_VG) $(INCLUDES) -I tests/	\
	    $(TEST_SRCS) $(LIB_VG)			\
	    -o $(TEST_BIN_VG)
