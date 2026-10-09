# WebDAV Client WSA

Native read-write WebDAV-to-FUSE client and boot-time drive reconciler for Windows Subsystem for Android (WSA).

## Status — full read-write client (v0.2.0)

`webdavfs` is a complete WebDAV FUSE filesystem (raw FUSE kernel protocol, no libfuse): PROPFIND/GET(Range)/PUT/DELETE/MKCOL/COPY/MOVE, HTTP Basic auth, optional HTTPS via static mbedTLS, directory cache, buffered writes flushed with PUT, `-d` daemon mode, and `--selftest`. The CI smoke tests run `--selftest` and verify graceful mount failure. On-device behavior (FUSE under WSA, SELinux context, media visibility) still requires manual testing.

## Release assets

- `webdavfs.sh` — Android/WSA drive registry poller and mount reconciler (state-tracked, rescan broadcast, EARLY log parity).
- `webdavfs-x86_64` — static x86_64 musl ELF (with mbedTLS).
- `webdavfs-aarch64` — static AArch64 musl ELF (with mbedTLS).
- `webdavfs-universal` — self-extracting launcher embedding both native ELFs and selecting by `uname -m`. This is a multi-architecture package, not one conventional ELF that runs on two CPU architectures.

## WSA loopback contract

From Windows, establish the ADB reverse mapping after WSA starts (and re-run if WSA loses it):

```powershell
adb reverse tcp:8085 tcp:8085
```

Inside WSA, the registry URL is `http://127.0.0.1:8085/info.json`; drive URLs are `http://127.0.0.1:8085/<letter>/`. No host/LAN IP discovery is used.

## Mount layout

Each enabled drive mounts at `/data/media/0/<sdcard label>` (labels sanitized; `/` and `\` become `_`), visible to all apps as `/sdcard/<label>`. The reconciler tracks mounts in `/data/adb/webdavfs-state`, broadcasts `MEDIA_MOUNTED` after changes, and retains existing mounts during registry outages (grace window, default 45s) to avoid detaching unrelated paths.

## Build

- CI: `.github/workflows/release.yml` cross-compiles mbedTLS 3.6.4 and `webdavfs` for x86_64/aarch64 musl with zig 0.13.0, runs the smoke test, and packages the assets.
- Local (no TLS): `CC=cc sh build/build.sh` builds a TLS-less binary for quick iteration; the shipped artifacts always include TLS.
