#!/bin/sh
set -eu
: "${CC:=cc}"
: "${OUT_DIR:=build/out}"
mkdir -p "$OUT_DIR"
"$CC" -Os -static -s -DVERSION='"0.1.0-dev"' -Wall -Wextra -Werror -o "$OUT_DIR/webdavfs" src/webdavfs.c
"$OUT_DIR/webdavfs" --version
