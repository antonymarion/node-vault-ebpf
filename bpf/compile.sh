#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

CLANG="${CLANG:-clang}"
ARCH_DEF="${ARCH_DEF:--D__TARGET_ARCH_x86}"

SYS_INCLUDES=$("$CLANG" -v -E - </dev/null 2>&1 \
  | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

echo "Using clang: $($CLANG --version | head -n1)"
echo "SYS_INCLUDES=$SYS_INCLUDES"

set -x
"$CLANG" -O2 -g -target bpf "$ARCH_DEF" \
  $SYS_INCLUDES \
  -c rewrite.bpf.c -o rewrite.bpf.o
llvm-objdump -h rewrite.bpf.o | head -n 30
