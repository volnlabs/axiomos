#!/bin/sh
set -eu

src_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out_dir=${1:-"$src_dir/../../../target/managed-bpf"}

command -v clang >/dev/null
command -v llvm-objcopy >/dev/null
mkdir -p "$out_dir"

for name in conservative_obstacle slow_approach clear_streak; do
    clang -target bpfel -mcpu=v3 -O2 -g0 -Wall -Werror \
        -c "$src_dir/$name.c" -o "$out_dir/$name.o"
    llvm-objcopy --only-section=.text -O binary \
        "$out_dir/$name.o" "$out_dir/$name.bin"
done

echo "managed BPF raw instructions: $out_dir"
