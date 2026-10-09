#!/bin/sh
set -eu
bin="${1:-build/out/webdavfs}"
"$bin" --version | grep -q webdavfs
"$bin" --selftest
"$bin" --help >/dev/null
if "$bin" http://127.0.0.1:8085/c/ /nonexistent >/tmp/webdavfs-smoke.out 2>&1; then
  echo 'Unexpected mount success' >&2
  exit 1
fi
grep -Eq 'not a directory|cannot open /dev/fuse|mount failed' /tmp/webdavfs-smoke.out
echo 'Smoke tests passed (version, selftest, graceful mount failure).'
