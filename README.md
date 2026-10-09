<div align="center">

# WebDAV Client WSA

### Native read-write WebDAV FUSE client for Windows Subsystem for Android

![Version](https://img.shields.io/badge/version-0.2.0-blue?style=for-the-badge)
![WSA](https://img.shields.io/badge/WSA-any-rooted-green?style=for-the-badge)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Platform](https://img.shields.io/badge/platform-WSA_(x86__64%2FAArch64)-4caf50?style=for-the-badge)
![License](https://img.shields.io/badge/License-Source--Available-blue?style=for-the-badge)

**Mount Windows folders inside WSA as normal Android storage — full read-write, no APK, no root-permission dialogs, no host-IP discovery.**

Part of the [WSA Installer](https://github.com/WSA-Installer) organization.

[Release Assets](../../releases) · [Quick Start](#quick-start) · [Architecture](docs/architecture.md) · [Registry Contract](docs/registry-contract.md) · [Reconciler](docs/reconciler.md) · [Building](docs/building.md)

</div>

---

<br>

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Release Assets](#release-assets)
- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Building](#building)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)
- [License](#license)

---

<br>

## Introduction

**WebDAV Client WSA** lets any Android app inside WSA read and write files on Windows shares that are published by the [WSA Installer](https://github.com/WSA-Installer) host application's built-in WebDAV server — without copying files, without an APK, and without granting root to any app.

It works in two layers:

| Layer | Component | Role |
|:------|:----------|:-----|
| **Filesystem** | `webdavfs` (static C binary) | A full read-write WebDAV client exposed as a FUSE mount |
| **Orchestrator** | `webdavfs.sh` (POSIX shell) | Boot-time reconciler that polls the host registry and mounts/unmounts drives |

Both files are injected into WSA's `initrd.img` by [TWRP for WSA](https://github.com/WSA-Installer/twrp-for-wsa) alongside the existing Magisk hook, and launched automatically in the background on every boot.

### What It Does

| Capability | Description |
|:-----------|:------------|
| **Full read-write** | Create, rename, move, copy, delete files and folders — all mapped to WebDAV verbs (PROPFIND, GET, PUT, DELETE, MKCOL, MOVE, COPY) |
| **Any install type** | Mount lives at `/data/media/0/<label>` — visible to **all** apps (system/user/isolated) as `/sdcard/<label>` |
| **Zero-permission model** | No app needs root, `MANAGE_EXTERNAL_STORAGE`, or a storage-volume declaration |
| **Loopback-only** | Talks exclusively to `http://127.0.0.1:8085` via `adb reverse` — no LAN/host-IP discovery, no firewall exposure |
| **Static, tiny** | Single musl-static binary (~700 KB with mbedTLS), no libfuse, no runtime deps |
| **HTTPS optional** | Built-in mbedTLS; verification off by default for the loopback threat model |

---

<br>

## Features

### Filesystem (`webdavfs`)

- **Raw FUSE kernel protocol** — no libfuse dependency; the binary speaks `/dev/fuse` directly
- **All core WebDAV verbs** — `OPTIONS`, `PROPFIND` (Depth 0/1), `HEAD`, `GET` (with `Range`), `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`
- **HTTP Basic authentication** — `user=`/`pass=` mount options
- **Optional HTTPS** — static mbedTLS; `ssl_verify=0|1` and `ca_path=` options
- **Directory + attribute cache** — TTL-based (default 2 s), invalidation on writes
- **Buffered writes** — dirty files are flushed with a single `PUT` on close/fsync (cap: `max_write_file=`, default 256 MB)
- **Read-window cache** — 1 MB range cache to smooth sequential reads
- **Daemon mode** — `-d` double-forks; `logfile=` and `pidfile=` options
- **`--selftest`** — offline validation of URL codec, XML, Base64, PROPFIND parser, HTTP date

### Reconciler (`webdavfs.sh`)

- **Registry polling** — every 3 s (configurable), `curl` or `wget`, loopback only
- **Mount tracking** — persistent state file (`/data/adb/webdavfs-state`) enables label-change remounts and unmounts of drives that disappear from the registry
- **Graceful outage handling** — existing mounts are **retained** during registry outages (45 s grace) to avoid detaching unrelated paths
- **Media rescan** — broadcasts `MEDIA_MOUNTED` after every mount/unmount so MTP and file managers see the change immediately
- **Triple logging** — `/data/adb/lsp-boot.log`, `/storage/emulated/0/WSA Installer/post-fs-data.log`, and the early-boot `post-fs-data.log` next to the script

---

<br>

## Release Assets

Every release ships **four files**:

| Asset | What it is |
|:------|:-----------|
| `webdavfs-x86_64` | Static x86_64 musl ELF (with mbedTLS) — for x64 WSA images |
| `webdavfs-aarch64` | Static AArch64 musl ELF (with mbedTLS) — for ARM64 WSA images |
| `webdavfs-universal` | Self-extracting `sh` launcher embedding both ELFs; picks the right one by `uname -m` |
| `webdavfs.sh` | The boot-time drive reconciler (POSIX `sh`, busybox/toybox-safe) |

The universal launcher is a multi-architecture **package**, not one ELF that runs on two CPU architectures — it extracts the correct payload at run time.

---

<br>

## System Requirements

- **WSA** (any rooted build — the Magisk hook from TWRP for WSA must be installed)
- **Windows 10/11** running the WSA Installer host app (provides the WebDAV server on `0.0.0.0:8085`)
- **`adb`** on the Windows side (bundled with TWRP for WSA)
- No Android-side app is required — the mount is global

---

<br>

## Quick Start

### 1. Install the hook (once)

If you have not already, install the Magisk hook via [TWRP for WSA](https://github.com/WSA-Installer/twrp-for-wsa):

```powershell
twrp.exe --install-magisk-hook
```

(This also injects `webdavfs` + `webdavfs.sh` automatically on current builds.)

### 2. Start the host WebDAV server

Launch the WSA Installer app on Windows; the built-in WebDAV server starts on port **8085** and publishes the registry at `/info.json`.

### 3. Establish the loopback tunnel

After WSA is running (re-run this whenever WSA restarts):

```powershell
adb reverse tcp:8085 tcp:8085
```

### 4. Reboot WSA

On the next boot the reconciler starts automatically, waits for `sys.boot_completed=1`, and mounts every drive whose registry entry has `"mount": true` at:

```
/sdcard/<sdcard label>/
```

…visible to **every** Android app, no permission prompts.

### 5. Toggle drives

Use the drive toggles in the WSA Installer host app. The reconciler picks up the change within ~3–5 s (poll interval + cache TTL) and mounts/unmounts accordingly — no reboot needed.

---

<br>

## How It Works

```
┌──────────────────────────── Windows ────────────────────────────┐
│  WSA Installer app                                              │
│    └─ WebDAV server 0.0.0.0:8085                               │
│         ├─ /info.json   ← registry (drives, mount flags)       │
│         └─ /c/ /d/ …    ← drive roots (SMB-backed)             │
└───────────────────────────────┬─────────────────────────────────┘
                                │ adb reverse tcp:8085 tcp:8085
┌───────────────────────────────▼───── WSA (Android) ─────────────┐
│  initrd.img (Magisk hook, injected by TWRP for WSA)             │
│    └─ post-fs-data.sh                                           │
│         └─ webdavfs.sh  (background, PID-guarded)               │
│              ├─ polls http://127.0.0.1:8085/info.json (3 s)     │
│              ├─ mounts:  webdavfs http://127.0.0.1:8085/<d>/    │
│              │           /data/media/0/<label> \                │
│              │           -o allow_other,context=…               │
│              └─ unmounts on mount:false or key removal          │
│                                                                 │
│  /data/media/0/<label>  =  /sdcard/<label>  (all apps)          │
└─────────────────────────────────────────────────────────────────┘
```

1. **Host** publishes drives via `info.json` (see [Registry Contract](docs/registry-contract.md)).
2. **Reconciler** (`webdavfs.sh`) polls the registry over the ADB-reverse loopback.
3. For each `"mount": true` drive it launches the **`webdavfs`** binary, which FUSE-mounts the WebDAV collection at `/data/media/0/<label>`.
4. Android's emulated storage maps `/data/media/0/*` to `/sdcard/*`, so the share appears as a normal folder to every app.

---

<br>

## Architecture

| Path (inside `initrd.img`) | Mode | Role |
|---|---|---|
| `overlay.d/sbin/webdavfs` | `0755` | Static FUSE WebDAV client (x86_64 or aarch64, auto-detected) |
| `overlay.d/sbin/webdavfs.sh` | `0755` | Boot-time drive reconciler |

The launcher block appended to `post-fs-data.sh` (by TWRP for WSA) is:

```sh
# --- webdavfs drive mounts (background) ---
WD="$(dirname "$0")/webdavfs.sh"
if [ -f "$WD" ]; then
    chmod 755 "$WD"
    ( "$WD" ) &
fi
# --- end webdavfs helper ---
```

Full details: [docs/architecture.md](docs/architecture.md).

---

<br>

## Building

CI (GitHub Actions) is the canonical build:

- **zig 0.13.0** cross-compiles `webdavfs.c` for `x86_64-linux-musl` and `aarch64-linux-musl`
- **mbedTLS 3.6.7** is built statically for each target from the official release tarball
- Smoke tests run on both architectures (`--version`, `--selftest`, `--help`, graceful mount rejection); aarch64 is exercised under **QEMU user-mode** (`qemu-aarch64-static`)
- The `package` job assembles the universal launcher and smoke-tests it on the host
- Tagged pushes publish all four assets as a GitHub prerelease

Local iteration (TLS-less, for quick checks):

```sh
CC=cc sh build/build.sh
sh tests/smoke_test.sh
```

Full details: [docs/building.md](docs/building.md).

---

<br>

## Documentation

| Document | Contents |
|:---------|:---------|
| [docs/architecture.md](docs/architecture.md) | Components, mount layout, FUSE/HTTP design, SELinux, size budget |
| [docs/registry-contract.md](docs/registry-contract.md) | `info.json` schema, loopback rules, host behavior |
| [docs/reconciler.md](docs/reconciler.md) | `webdavfs.sh` reference: options, state file, logging, failure modes |
| [docs/building.md](docs/building.md) | CI pipeline, mbedTLS cross-build, local builds, release process |

---

<br>

## Troubleshooting

| Symptom | Likely cause | Fix |
|:--------|:-------------|:----|
| `Registry fetch failed; outage=…s` in the log | `adb reverse` not active, or host server down | Re-run `adb reverse tcp:8085 tcp:8085`; start the WSA Installer app |
| `ERROR missing executable …/webdavfs` | Binary not injected, or wrong architecture | Re-run `twrp.exe --install-magisk-hook` (or `--repaire-magisk-hook`) |
| `ERROR mount failed drive=… exit=1` | `/dev/fuse` unavailable, or WebDAV server returned an error | Check `/data/adb/lsp-boot.log`; verify the drive opens in a Windows browser at `http://127.0.0.1:8085/<letter>/` |
| Mount exists but apps see `EIO` | Host went away (sleep/shutdown) while mounted | Reconciler retains mounts during outages by design; wake the host or toggle the drive off/on |
| Folder not visible in file managers immediately | Media store not rescanned | Reconciler broadcasts `MEDIA_MOUNTED`; force a rescan or open the path directly at `/sdcard/<label>` |

Logs (all three are written by the reconciler):

```sh
adb root
adb shell cat /data/adb/lsp-boot.log
# or, no root needed:
# C:\Users\…\AppData\Local\Packages\…\LocalState\sharedfs\storage\emulated\0\WSA Installer\post-fs-data.log
```

---

<br>

## Credits

- Built by the [WSA Installer](https://github.com/WSA-Installer) team
- Cross-compilation via [zig](https://ziglang.org/) · TLS via [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) · FUSE protocol per `linux/fuse.h`

---

<br>

## License

Source-available. See the repository for details.
