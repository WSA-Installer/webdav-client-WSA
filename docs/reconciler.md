# Reconciler (`webdavfs.sh`)

> The boot-time orchestrator that polls the host registry and keeps
> WebDAV mounts in sync with the Windows GUI toggles.

Code: `scripts/webdavfs.sh`. Launched in the background by the
`post-fs-data.sh` launcher block injected by
[TWRP for WSA](https://github.com/WSA-Installer/twrp-for-wsa).

---

## Invocation

The boot script appends (below the uninstall handler and the Play-Store
helper):

```sh
# --- webdavfs drive mounts (background) ---
WD="$(dirname "$0")/webdavfs.sh"
if [ -f "$WD" ]; then
    chmod 755 "$WD"
    ( "$WD" ) &
fi
# --- end webdavfs helper ---
```

The reconciler:

1. resolves the `webdavfs` binary as its **sibling**
   (`$(dirname "$0")/webdavfs`), falling back to `/data/adb/webdavfs`;
2. sources `/data/adb/webdavfs.conf` if present (see [Configuration](#configuration));
3. guards against double-start via `/data/adb/webdavfs-daemon.pid`;
4. waits for `sys.boot_completed=1`;
5. enters the reconcile loop.

---

## Configuration

Optional file: `/data/adb/webdavfs.conf` (sourced as `sh`):

| Variable | Default | Meaning |
|:---------|:--------|:--------|
| `POLL` | `3` | Registry poll interval, seconds |
| `GRACE` | `45` | Outage seconds before the "retaining mounts" log line (mounts are **never** force-removed on outage) |
| `USER` | *(empty)* | HTTP Basic username (passed to `webdavfs` via the mount command in a full deployment) |
| `PASS` | *(empty)* | HTTP Basic password |
| `SSL_VERIFY` | `0` | `1` = verify HTTPS certificates (loopback normally needs `0`) |
| `MOUNT_OPTS` | `allow_other,context=u:object_r:media_rw_data_file:s0` | FUSE mount options |

The binary path can be overridden by setting `BIN` in the conf file.

---

## State file

`/data/adb/webdavfs-state` — one `letter=label` line per mounted drive.

| Event | State update |
|:------|:-------------|
| Mount succeeds | `state_set <letter> <label>` |
| Label change | `state_del <letter>` (old), then mount + `state_set` (new) |
| `mount: false` | unmount, `state_del` |
| Key removed from registry | unmount, `state_del` |

The state file is what enables **rename remounts** and **gone-key
unmounts** — the registry snapshot alone cannot express "this letter was
previously mounted under a different label".

---

## Logging

Every log line is appended to **three** destinations (plus stdout):

| Path | Lifetime | Audience |
|:-----|:---------|:---------|
| `/data/adb/lsp-boot.log` | persistent across boots | debugging via `adb root` |
| `/storage/emulated/0/WSA Installer/post-fs-data.log` | persistent, user-accessible | end user (no root needed) |
| `$(dirname "$0")/post-fs-data.log` | tmpfs, wiped next boot | early-boot visibility in logcat |

Prefix: `[WebDAV]`. Typical session:

```
[WebDAV] Daemon started; waiting for boot completion
[WebDAV] Mount request drive=c label=C: Drive
[WebDAV] Mount command returned success: /data/media/0/C: Drive
[WebDAV] Mount request drive=d label=FlutterPro
[WebDAV] Mount command returned success: /data/media/0/FlutterPro
```

---

## Media rescan

After every successful mount **and** unmount the reconciler broadcasts:

```
am broadcast -a android.intent.action.MEDIA_MOUNTED -d file:///sdcard
```

so MTP, `MediaStore` and file managers pick up the change immediately
instead of waiting for the next periodic scan.

---

## Failure modes

| Condition | Behavior |
|:----------|:---------|
| `curl` and `wget` both missing | `fetch_registry` returns 127; outage counter runs; mounts retained |
| Registry returns non-JSON / garbage | Parse helpers yield empty; no mounts change; next poll retries |
| `webdavfs` binary missing | `mount_drive` logs `ERROR missing executable …` and returns 1; state not updated |
| `mount(2)` fails (no `/dev/fuse`, SELinux denial) | `ERROR mount failed drive=… exit=…`; logged to all three logs |
| Unmount tool missing (`fusermount`/`umount`) | `unmount_drive` returns 1; state entry stays; retried next cycle |
| Script killed (SIGINT/SIGTERM) | PID file removed via `trap`; next boot restarts cleanly |

**Outage policy:** existing mounts are always retained during registry
outages. Force-unmounting on a transient host hiccup would yank the FUSE
connection out from under apps mid-write. Reads/writes surface `EIO`
until the host returns — same semantics as a desktop network drive.

---

## Dependencies (inside WSA)

| Tool | Used for | Fallback |
|:-----|:---------|:---------|
| `curl` or `wget` | registry fetch | none (outage counter) |
| `grep`, `sed`, `tr`, `head` | JSON field extraction | toybox equivalents |
| `fusermount` or `umount` | unmount | none (logged error) |
| `am` | media rescan broadcast | skipped silently |
| `getprop` | boot-completion wait | — |

No `jq`, no Python, no Android SDK — pure POSIX `sh` + busybox/toybox
applets, safe for any Magisk-hooked WSA build.
