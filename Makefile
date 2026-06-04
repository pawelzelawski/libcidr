# Makefile - libcidr
#
# Targets:
#   make / make dev    - debug build with ASan/UBSan (Linux only), runs tests
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
#   make python-dev    - build CPython extension with ASan/UBSan
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

CFLAGS_COMMON = -std=c11 -Wall -Wextra -Wpedantic		\
                -Wno-unused-parameter				\
                -fno-omit-frame-pointer				\
                -D_POSIX_C_SOURCE=200809L			\
                -D_XOPEN_SOURCE=700

# Platform flags
CFLAGS_OS != if [ "$(OS)" = "Linux" ]; then echo "-DCIDR_LINUX"; \
              elif [ "$(OS)" = "OpenBSD" ]; then echo "-DCIDR_OPENBSD"; \
              else echo ""; fi

# ASan/UBSan - Linux only; OpenBSD clang does not ship sanitizer runtimes
SANITIZERS != if [ "$(OS)" = "Linux" ]; then echo "-fsanitize=address,undefined"; else echo ""; fi

CFLAGS_DEV     = $(CFLAGS_COMMON) $(CFLAGS_OS)			\
                 -O1 -g					\
                 -Werror						\
                 $(SANITIZERS)					\
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

TEST_SRCS = tests/run_tests.c

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

PY        != command -v python3 2>/dev/null || echo python3
PYCONFIG  != command -v python3-config 2>/dev/null || echo python3-config
PYINC     != $(PYCONFIG) --includes 2>/dev/null || echo ""
PYLDFLAGS != $(PYCONFIG) --ldflags --embed 2>/dev/null || echo ""
PYSUFFIX  != $(PY) -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))" 2>/dev/null || echo ""

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

.PHONY: all dev release test test-tsan valgrind lint format clean install	\
        python-ext python-check-abi python-dev test-python

all: dev

# --- dev: debug build + run tests ---------------------------------------------

dev: $(TEST_BIN)
	$(TEST_BIN)

# --- release: optimised static library -----------------------------------------

release: $(LIB_RELEASE)

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
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -c src/cidr_addr.c     -o $(TSAN_DIR)/cidr_addr.o
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -c src/cidr_prefix.c   -o $(TSAN_DIR)/cidr_prefix.o
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -c src/cidr_bulk.c     -o $(TSAN_DIR)/cidr_bulk.o
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -c src/cidr_classify.c  -o $(TSAN_DIR)/cidr_classify.o
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -c src/cidr_index.c     -o $(TSAN_DIR)/cidr_index.o
	ar rcs $(LIB_TSAN)						\
	    $(TSAN_DIR)/cidr_addr.o					\
	    $(TSAN_DIR)/cidr_prefix.o					\
	    $(TSAN_DIR)/cidr_bulk.o					\
	    $(TSAN_DIR)/cidr_classify.o				\
	    $(TSAN_DIR)/cidr_index.o
	$(CC) $(CFLAGS_TSAN) $(INCLUDES) -I tests/			\
	    $(TEST_SRCS) $(LIB_TSAN)				\
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

python-ext: $(PY_DIR)/libcidr$(PYSUFFIX)

$(PY_DIR)/_libcidr_ext.o: $(PY_DIR)/_libcidr_ext.c include/libcidr.h
	$(CC) $(CFLAGS_PYEXT) -c $< -o $@

$(PY_DIR)/libcidr$(PYSUFFIX): $(PY_DIR)/_libcidr_ext.o $(LIB_RELEASE)
	$(CC) -shared $(PYLDFLAGS) $^ -o $@

python-check-abi:
	@echo "Extension suffix: $(PYSUFFIX)"
	@echo "$(PYSUFFIX)" | grep -q "abi3" || \
	    (echo "ERROR: extension was not built against stable ABI"; exit 1)

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
	$(CC) -shared $(PYLDFLAGS)					\
	      $(BUILD_DIR)/pydev/_libcidr_ext.o $(LIB_DEV)		\
	      -o $(PY_DIR)/libcidr$(PYSUFFIX)

test-python: $(PY_DIR)/libcidr$(PYSUFFIX)
	PYTHONPATH=$(PY_DIR) $(PY) -m unittest tests.test_python -v

# --- Benchmarks (Phase 8) -----------------------------------------------------
# Built under release flags. Stubs until implemented.

bench:
	@echo "Benchmarks not yet implemented (Phase 8)"

# --- lint: clang-tidy + cppcheck -----------------------------------------------

lint:
	clang-tidy $(LIB_SRCS) -- $(CFLAGS_DEV) $(INCLUDES)
	@if command -v cppcheck >/dev/null 2>&1; then \
	    cppcheck --enable=all --error-exitcode=1		\
	             --suppress=missingIncludeSystem		\
	             --suppress=unusedFunction			\
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