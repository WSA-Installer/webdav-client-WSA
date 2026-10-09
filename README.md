# WebDAV Client WSA

Native WebDAV-to-FUSE client and boot-time drive reconciler for Windows Subsystem for Android (WSA).

## Current status — development scaffold

**The C executable is not yet a functional WebDAV filesystem.** It deliberately refuses mount requests rather than pretending to mount or risk user data. The workflow currently validates cross-compilation and packaging only. Do not deploy it as a working filesystem yet.

## Planned release assets

- `webdavfs.sh` — Android/WSA drive registry poller and mount reconciler.
- `webdavfs-x86_64` — static x86_64 ELF build.
- `webdavfs-aarch64` — static AArch64 ELF build.
- `webdavfs-universal` — self-extracting launcher embedding both native ELFs and selecting by `uname -m`. This is a multi-architecture package, not one conventional ELF that runs on two CPU architectures.

## WSA loopback contract

From Windows, establish the ADB reverse mapping after WSA starts (and re-run if WSA loses it):

```powershell
adb reverse tcp:8085 tcp:8085
```

Inside WSA, the registry URL is `http://127.0.0.1:8085/info.json`; drive URLs are `http://127.0.0.1:8085/<letter>/`. No host/LAN IP discovery is used.

## Production readiness

The FUSE/WebDAV operation engine, HTTP parsing, authentication, retries, write flushing, cache invalidation, HTTPS/TLS verification, SELinux behavior, and Android media visibility still require implementation and target-device testing. A green packaging workflow is not proof of filesystem correctness.
