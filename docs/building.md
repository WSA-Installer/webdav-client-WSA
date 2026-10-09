# Building

> The canonical build runs on GitHub Actions. Local builds are for quick
> iteration only (TLS-less).

Workflow: `.github/workflows/release.yml`. Local helper: `build/build.sh`.

---

## CI pipeline (canonical)

Triggered on every push to `main`, tags `v*`, pull requests, and manual
dispatch.

### Job 1 — `build-native` (matrix: x86_64 + aarch64)

1. **Checkout** + **setup-zig 0.13.0** (`mlugg/setup-zig@v2`)
2. **Build mbedTLS 3.6.7 (static, cross)**
   - Official release tarball (`mbedtls-3.6.7.tar.bz2`) — chosen over the
     git tag archive because the release tarball vendors the `framework/`
     scripts required by the library Makefile
   - `make -C library` with `CC="zig cc -target <target>"`, `AR="zig ar"`
   - Produces `libmbedcrypto.a`, `libmbedx509.a`, `libmbedtls.a`
3. **Compile `webdavfs`**
   - `zig cc -target <target> -Os -static -s -DVERSION='"0.2.0"' -Wall -Wextra -Werror`
   - Links the three mbedTLS archives
4. **Smoke test**
   - x86_64: runs natively on the ubuntu-24.04 runner
   - aarch64: runs under **QEMU user-mode** (`qemu-aarch64-static`, installed via apt)
   - Checks: `--version`, `--selftest`, `--help`, and graceful rejection of
     a nonexistent mountpoint (must fail with a recognized error, not
     succeed)
5. **Upload artifact** (`native-x86_64` / `native-aarch64`)

### Job 2 — `package` (needs `build-native`)

1. Download both native artifacts
2. **Assemble the universal launcher** — a self-extracting `sh` script:
   - header (launcher code) + `__WEBDAVFS_PAYLOAD_BELOW__` marker +
     `tar.gz` of both ELFs
   - at run time: extracts to `$TMPDIR`, picks the binary by `uname -m`
     (`x86_64|amd64` → x86_64, `aarch64|arm64` → aarch64), `exec`s it
3. **Smoke-test the universal launcher** on the host (x86_64 path)
4. `sh -n` syntax-check `webdavfs.sh`; verify all four assets are non-empty
5. Upload `webdavfs-release-assets` artifact
6. **On tags (`v*`)**: publish a GitHub **prerelease** with all four files

---

## Release assets

| Asset | Notes |
|:------|:------|
| `webdavfs-x86_64` | static musl ELF, mbedTLS linked, stripped |
| `webdavfs-aarch64` | static musl ELF, mbedTLS linked, stripped |
| `webdavfs-universal` | self-extracting launcher (multi-arch **package**, not a fat binary) |
| `webdavfs.sh` | reconciler script, `chmod 755` |

---

## Local build (TLS-less)

For quick iteration on the C source without the mbedTLS cross-build:

```sh
CC=cc sh build/build.sh
```

This compiles with `-DWEBDAVFS_WITH_TLS=0` (no mbedTLS), runs
`--version` and `--selftest`, and leaves the binary at
`build/out/webdavfs`.

Smoke tests:

```sh
sh tests/smoke_test.sh build/out/webdavfs
```

> **Note:** local TLS-less builds are **not** shippable — the shipped
> artifacts always include mbedTLS (CI builds them). Use local builds only
> to validate parser/logic changes quickly.

---

## Versioning

The version string is defined in one place and passed at compile time:

```sh
-DVERSION='"0.2.0"'
```

`build/build.sh` and the CI workflow both pass the same value. Bump it in
**both** files when cutting a release, then tag:

```sh
git tag v0.2.0
git push origin v0.2.0
```

The tag triggers the CI release job.

---

## Toolchain choices

| Tool | Why |
|:-----|:----|
| **zig cc** | First-class cross-compiler to musl-static targets; no separate sysroot management; `zig ar` for archives |
| **musl** | Fully static binaries; no bionic/glibc version skew on the Android side |
| **mbedTLS** | Small, embeddable TLS; builds cleanly with zig; Apache-2.0 OR GPLv2-compatible licensing |
| **QEMU user-mode** | Enables aarch64 smoke tests on the x86_64 runner without a second runner type |
| **POSIX sh** (reconciler) | busybox/toybox-safe on any Magisk-hooked WSA; no runtime deps |

---

## Reproducing a CI build locally (advanced)

Requires Linux (or WSL) with `make`, `curl`, and zig 0.13.0 on `PATH`:

```sh
MBEDTLS_VERSION=3.6.7
curl -fsSL "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2" -o /tmp/mbedtls.tar.bz2
tar -xjf /tmp/mbedtls.tar.bz2 -C /tmp
make -C "/tmp/mbedtls-${MBEDTLS_VERSION}/library" -j"$(nproc)" \
  CC="zig cc -target x86_64-linux-musl" AR="zig ar" CFLAGS="-Os -fPIC" \
  libmbedcrypto.a libmbedx509.a libmbedtls.a

zig cc -target x86_64-linux-musl -Os -static -s \
  -DVERSION='"0.2.0"' -Wall -Wextra -Werror \
  -I "/tmp/mbedtls-${MBEDTLS_VERSION}/include" \
  src/webdavfs.c \
  "/tmp/mbedtls-${MBEDTLS_VERSION}/library/libmbedtls.a" \
  "/tmp/mbedtls-${MBEDTLS_VERSION}/library/libmbedx509.a" \
  "/tmp/mbedtls-${MBEDTLS_VERSION}/library/libmbedcrypto.a" \
  -o dist/webdavfs-x86_64
```
