# Architecture

> How the two layers fit together, how a mount is established, and the
> design constraints that shaped the implementation.

Component code: `src/webdavfs.c` (filesystem), `scripts/webdavfs.sh`
(reconciler). Injection into `initrd.img`: `twrp.py` in
[twrp-for-wsa](https://github.com/WSA-Installer/twrp-for-wsa)
(`inject_webdavfs_files()`, `build_boot_script()`).

---

## Components

| Layer | File | Language | Runtime |
|:------|:-----|:---------|:--------|
| Filesystem | `webdavfs` | C99 (single file) | static musl ELF, no deps |
| Orchestrator | `webdavfs.sh` | POSIX `sh` | busybox/toybox applets only |

They are deliberately independent: the reconciler invokes the binary as a
subprocess; the binary knows nothing about the registry.

---

## Mount layout

Each enabled drive is mounted at:

```
/data/media/0/<sanitized sdcard label>/
```

Android's FUSE-based emulated storage exposes `/data/media/0/*` as
`/sdcard/*` to **all** apps — regardless of install type (system, user,
isolated). This is the key design choice:

| Alternative | Why not |
|:-------------|:--------|
| `StorageVolume` (Settings → Storage) | Requires a block device or vold integration; impossible without deep system modification |
| Per-app `Storage Access Framework` | Requires an APK + user grant per app |
| `bind` into `/sdcard` | Same as `/data/media/0` but adds a redundant mount |
| Root-only path (`/data/media/0` needs no app root) | ✅ chosen — zero-permission model |

**Limitation (accepted):** the share does not appear in *Settings →
Storage* (that list is vold-driven). Apps reach it via the normal
`/sdcard/<label>` path.

---

## FUSE design (`webdavfs`)

### Protocol

The binary speaks the **raw FUSE kernel protocol** on `/dev/fuse` — no
libfuse, no `fusermount` helper. Mount is performed with the `mount(2)`
syscall (`fstype="fuse"`, `fd=N,rootmode=40000,user_id=…,group_id=…`).

Supported opcodes: `INIT`, `LOOKUP`, `GETATTR`, `SETATTR`, `OPENDIR`,
`READDIR`, `OPEN`, `CREATE`, `READ`, `WRITE`, `RELEASE`, `FLUSH`, `FSYNC`,
`UNLINK`, `MKDIR`, `RMDIR`, `RENAME`, `STATFS`. Everything else returns
`ENOSYS` (kernel falls back or surfaces a clean error).

### HTTP/WebDAV layer

- One TCP connection per request (`Connection: close`) — simplest correct
  model for a network filesystem; TLS session reuse handled by mbedTLS
  where applicable
- Chunked transfer decoding supported
- `Range:` reads for large files (1 MB read-window cache)
- `Depth: 1` PROPFIND for listings, `Depth: 0` for self-stat
- Namespace-tolerant XML parsing (`<D:href>` = `<href>`)

### Write path

Writes go to an in-memory buffer (per open handle, cap `max_write_file=`,
default 256 MB). On `FLUSH`/`RELEASE`/`FSYNC` the buffer is sent as a
single `PUT`. This matches WebDAV semantics (no partial PUTs) and avoids
hammering the server with small writes.

### Caches

| Cache | Key | TTL / invalidation |
|:------|:----|:-------------------|
| Directory listing | path | `cache_ttl=` (default 2 s); invalidated by MKDIR/RMDIR/RENAME/CREATE/UNLINK |
| Attribute | inode | same TTL; refreshed on GETATTR |
| Read window | inode + offset | 1 MB; replaced on miss |

The short TTL keeps the client honest under concurrent host-side changes
(the host rescans drives every second).

---

## Reconciler design (`webdavfs.sh`)

### Loop

```
wait for sys.boot_completed=1
loop every POLL (default 3 s):
    fetch http://127.0.0.1:8085/info.json
    for each drive letter c..z:
        mount:true   → mount if not mounted (state-tracked)
        mount:false  → unmount if mounted
        label change → unmount old, mount new
    for each state entry whose key vanished from the registry:
        unmount
    on fetch failure:
        accumulate outage seconds; at GRACE (45 s) log and reset
        (mounts are RETAINED — never force-unmounted on outage)
```

### State file

`/data/adb/webdavfs-state` — lines of `letter=label`. Enables:

- **Label-change detection** (unmount old path before mounting new)
- **Gone-key unmount** (drive removed from registry → unmount)

Without the state file the reconciler could only act on the *current*
registry snapshot and would leak mounts on renames.

### Why retain on outage?

A registry outage means the **host** is unreachable (sleep, crash,
network hiccup). Force-unmounting would yank the FUSE connection out
from under apps mid-write, risking data loss. Retaining keeps the mount
alive; reads/writes surface `EIO` until the host returns — the same
semantics as a network drive on a desktop OS.

---

## SELinux

Mount options passed to the kernel:

```
allow_other,context=u:object_r:media_rw_data_file:s0
```

- `allow_other` — any UID may access the mount (required for the
  all-apps model)
- `context=…` — labels the FUSE tree as `media_rw_data_file`, the same
  label as real `/data/media` storage, so untrusted apps can read/write
  without policy changes

---

## Connectivity contract

**Loopback via ADB reverse only.**

```
Windows:  adb reverse tcp:8085 tcp:8085
WSA:      http://127.0.0.1:8085/info.json   (registry)
          http://127.0.0.1:8085/<letter>/   (drive roots)
```

No host-IP discovery, no mDNS, no LAN addresses. Rationale:

- The Windows host IP is **not discoverable from Android** in a stable way
  (interfaces change, VPNs interfere)
- Loopback + `adb reverse` needs no firewall holes
- The registry server binds `0.0.0.0` on the host, but that is a host-side
  decision — the Android side never learns or uses the LAN address

The host rewrites the `path` field in `info.json` to the loopback origin
before serving it to Android.

---

## Size budget

| Piece | Size (approx.) |
|:------|:---------------|
| `webdavfs` (x86_64, static, mbedTLS, stripped) | ~700 KB |
| `webdavfs.sh` | ~4 KB |
| **Total injected** | **< 1 MB** |

Well inside the initrd budget; no compression needed.

---

## Security model

- **No secrets on disk** — credentials (if any) live in the mount command
  line / conf file with `0600`, root-only
- **Loopback only** — the WebDAV traffic never leaves the host↔WSA pair
- **TLS optional** — for the loopback threat model, mbedTLS verification
  is off by default (`ssl_verify=0`); flip it on for untrusted networks
  (not the intended deployment)
- **Fail-closed binary** — without a valid URL + mountpoint the binary
  refuses to do anything; the CI smoke tests enforce this
