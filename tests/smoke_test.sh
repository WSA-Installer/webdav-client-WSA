#!/bin/sh
set -eu
bin="${1:-build/out/webdavfs}"
"$bin" --version | grep -q webdavfs
if "$bin" http://127.0.0.1:8085/c/ /tmp/webdavfs-test >/tmp/webdavfs-smoke.out 2>&1; then echo 'Unexpected mount success' >&2; exit 1; fi
grep -q 'operation engine is not implemented' /tmp/webdavfs-smoke.out
echo 'Smoke tests passed (version and fail-closed behavior).'
