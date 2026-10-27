#!/bin/bash
# Build src/parse.c as a shared library with ASan/UBSan and run the
# Hypothesis property tests against it. Extra arguments go to pytest.
#
#   tests/proptest/run.sh                       quick run (CI-sized)
#   KB_PROPTEST_EXAMPLES=100000 tests/proptest/run.sh   long soak
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BUILD=$HERE/build

mkdir -p "$BUILD"
if [[ ! -x "$BUILD/venv/bin/python" ]]; then
	python3 -m venv "$BUILD/venv"
fi
if ! cmp -s "$HERE/requirements.txt" "$BUILD/venv/requirements.txt"; then
	"$BUILD/venv/bin/pip" install -q -r "$HERE/requirements.txt"
	cp "$HERE/requirements.txt" "$BUILD/venv/requirements.txt"
fi

gcc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fPIC -shared \
	-fsanitize=address,undefined -fno-sanitize-recover=undefined \
	-fno-omit-frame-pointer -I"$REPO/src" \
	"$REPO/src/parse.c" -o "$BUILD/libkbparse.so"

# Python is not built with ASan, so the runtime has to be preloaded; buffers
# handed to the library come from the intercepted malloc and carry redzones.
LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1 \
KB_PARSE_LIB="$BUILD/libkbparse.so" \
	exec "$BUILD/venv/bin/python" -m pytest -s -q -p no:cacheprovider "$HERE" "$@"
