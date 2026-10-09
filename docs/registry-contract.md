# Registry Contract (`info.json`)

> The JSON document the host WebDAV server publishes for the reconciler.

Producer: `app.py` in [wsa_installer_download](https://github.com/WSA-Installer)
(host application). Consumer: `scripts/webdavfs.sh`.

---

## Endpoint

```
GET http://127.0.0.1:8085/info.json
```

- **Loopback only** on the Android side (via `adb reverse tcp:8085 tcp:8085`)
- Host binds the server on `0.0.0.0:8085`; the Android client never uses
  the LAN address
- Request header `Accept: application/json` is sent by the reconciler;
  browsers (Accept: text/html) receive a human-readable HTML page instead

---

## Schema

A single flat JSON object. **Keys are drive letters** (lowercase `c`–`z`).
Each value is an object:

```json
{
  "c": { "mount": true,  "path": "http://127.0.0.1:8085/c/", "sdcard": "C: Drive" },
  "d": { "mount": false, "path": "http://127.0.0.1:8085/d/", "sdcard": "FlutterPro" },
  "e": { "mount": true,  "path": "http://127.0.0.1:8085/e/", "sdcard": "multiOS USB" },
  "f": { "mount": true,  "path": "http://127.0.0.1:8085/f/", "sdcard": "VTOYEFI" }
}
```

| Field | Type | Meaning |
|:------|:-----|:--------|
| *(key)* | string | Drive letter, lowercase (`"c"` … `"z"`) |
| `mount` | bool | **Windows GUI toggle.** `true` = the reconciler should mount this drive; `false` = unmount (or never mount) |
| `path` | string | Full WebDAV URL of the drive root. **Origin is rewritten to loopback** before serving to Android |
| `sdcard` | string | Display name / mount label. Sanitized by the reconciler (`/` and `\` → `_`); used as the directory name under `/data/media/0/` |

---

## Host behavior

- The host rescans available drives on **every** `/info.json` GET, plus a
  **1 s filesystem watcher** for instant reaction to plug/unplug
- Toggling a drive's checkbox in the Windows GUI flips its `mount` value;
  the reconciler picks up the change within one poll cycle (≤ ~5 s)
- Entries are **added/updated/removed** as drives appear/disappear —
  there is no separate "remove" flag; a missing key means the drive is gone

---

## Consumer behavior (`webdavfs.sh`)

For each letter `c`–`z`:

| Registry state | Reconciler action |
|:---------------|:------------------|
| key present, `mount: true` | Mount `path` at `/data/media/0/<sdcard>` if not already mounted (state-tracked) |
| key present, `mount: false` | Unmount if mounted; remove from state |
| key present, `mount: true`, **label changed** | Unmount old label path, mount new |
| **key absent** (was in state) | Unmount (drive was removed from the host) |
| fetch fails | Retain all mounts; count outage seconds; log at `GRACE` (45 s) |

Label sanitization (reconciler side):

```
/ and \  →  _
trim leading/trailing whitespace
empty / "." / ".."  →  fallback "<LETTER>: Drive"
```

---

## Examples

### Enable drive D:

Host GUI: check *FlutterPro*. Registry becomes:

```json
"d": { "mount": true, "path": "http://127.0.0.1:8085/d/", "sdcard": "FlutterPro" }
```

Reconciler (≤ 5 s later):

```
[WebDAV] Mount request drive=d label=FlutterPro
[WebDAV] Mount command returned success: /data/media/0/FlutterPro
```

App sees: `/sdcard/FlutterPro/`

### Rename the label

Host changes `sdcard` to `Flutter Pro 2`. Reconciler:

```
[WebDAV] Unmounted /data/media/0/FlutterPro
[WebDAV] Mount request drive=d label=Flutter Pro 2
[WebDAV] Mount command returned success: /data/media/0/Flutter Pro 2
```

### Unplug the USB drive

Host removes key `"e"` from the registry. Reconciler:

```
[WebDAV] Unmounted /data/media/0/multiOS USB
```

### Host sleeps (registry unreachable)

```
[WebDAV] Registry fetch failed; outage=3s
[WebDAV] Registry fetch failed; outage=6s
…
[WebDAV] Registry grace exceeded; retaining mounts to avoid detaching unrelated paths
```

Mounts stay alive; reads/writes return `EIO` until the host returns.

---

## Non-goals

- **No authentication on the registry** — it is loopback-only and
  contains no secrets (paths + display names)
- **No drive-letter auto-assignment** — the host assigns letters from
  Windows; the reconciler only mirrors them
- **No write-through to the registry** — Android never mutates
  `info.json`; toggling is a host-side (Windows GUI) action
