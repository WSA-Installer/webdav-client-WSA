#!/system/bin/sh
# WSA WebDAV drive reconciler; requires a functional webdavfs binary and FUSE.
# On Windows after WSA startup: adb reverse tcp:8085 tcp:8085
TAG='[WebDAV]'; CONF='/data/adb/webdavfs.conf'; REGISTRY='http://127.0.0.1:8085/info.json'
SELFDIR=$(dirname "$0")
LOG='/data/adb/lsp-boot.log'; APPLOG='/storage/emulated/0/WSA Installer/post-fs-data.log'
EARLYLOG="$SELFDIR/post-fs-data.log"
PIDFILE='/data/adb/webdavfs-daemon.pid'; STATE='/data/adb/webdavfs-state'
BIN="$SELFDIR/webdavfs"
POLL=3; GRACE=45; USER=''; PASS=''; SSL_VERIFY=0
MOUNT_OPTS='allow_other,context=u:object_r:media_rw_data_file:s0'
log(){ line="$TAG $*"; echo "$line" >> "$LOG" 2>/dev/null; echo "$line" >> "$APPLOG" 2>/dev/null; echo "$line" >> "$EARLYLOG" 2>/dev/null; echo "$line"; }
prop(){ getprop "$1" 2>/dev/null; }
fetch_registry(){ if command -v curl >/dev/null 2>&1; then curl -fsS --connect-timeout 2 --max-time 5 "$REGISTRY"; elif command -v wget >/dev/null 2>&1; then wget -q -T 5 -O - "$REGISTRY"; else return 127; fi; }
json_obj(){ echo "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\{[^}]*" | head -n 1; }
json_bool(){ json_obj "$1" "$2" | grep -oE '"mount"[[:space:]]*:[[:space:]]*(true|false)' | head -n 1 | sed -E 's/.*:[[:space:]]*//'; }
json_label(){ json_obj "$1" "$2" | grep -oE '"sdcard"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/^[^"]*"sdcard"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' | head -n 1; }
clean_label(){ label=$(printf '%s' "$1" | tr '/\\' '__' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); case "$label" in ''|.|..) label="$2: Drive";; esac; printf '%s' "$label"; }
mounted(){ grep -F " $1 " /proc/mounts >/dev/null 2>&1; }
rescan_media(){ if command -v am >/dev/null 2>&1; then am broadcast -a android.intent.action.MEDIA_MOUNTED -d file:///sdcard >/dev/null 2>&1; fi; }
state_get(){ [ -r "$STATE" ] && sed -n "s/^$1=//p" "$STATE" | head -n 1; }
state_set(){ key="$1"; val="$2"; [ -w "$STATE" ] || : > "$STATE"; grep -v "^$key=" "$STATE" > "$STATE.tmp" 2>/dev/null; mv "$STATE.tmp" "$STATE" 2>/dev/null; printf '%s=%s\n' "$key" "$val" >> "$STATE"; }
state_del(){ key="$1"; [ -w "$STATE" ] || return 0; grep -v "^$key=" "$STATE" > "$STATE.tmp" 2>/dev/null; mv "$STATE.tmp" "$STATE" 2>/dev/null; }
mount_drive(){ letter="$1"; label="$2"; target="/data/media/0/$label"; mounted "$target" && return 0; mkdir -p "$target" || { log "ERROR creating $target"; return 1; }; [ -x "$BIN" ] || { log "ERROR missing executable $BIN"; return 1; }; log "Mount request drive=$letter label=$label"; "$BIN" "http://127.0.0.1:8085/$letter/" "$target" -o "$MOUNT_OPTS" >> "$LOG" 2>&1; rc=$?; if [ "$rc" -eq 0 ]; then log "Mount command returned success: $target"; rescan_media; else log "ERROR mount failed drive=$letter exit=$rc"; fi; return "$rc"; }
unmount_drive(){ target="$1"; if mounted "$target"; then if command -v fusermount >/dev/null 2>&1; then fusermount -u "$target"; elif command -v umount >/dev/null 2>&1; then umount "$target"; else return 1; fi; log "Unmounted $target"; rescan_media; fi; }
main(){
 umask 077; mkdir -p /data/adb
 if [ -r "$CONF" ]; then . "$CONF"; fi
 [ -x "$BIN" ] || { [ -x /data/adb/webdavfs ] && BIN='/data/adb/webdavfs'; }
 if [ -f "$PIDFILE" ]; then old=$(cat "$PIDFILE" 2>/dev/null); if [ -n "$old" ] && kill -0 "$old" 2>/dev/null && [ "$old" != "$$" ]; then log "Already running pid=$old"; exit 0; fi; fi
 echo "$$" > "$PIDFILE"; trap 'rm -f "$PIDFILE"' EXIT INT TERM
 case "$POLL" in ''|*[!0-9]*) POLL=3;; esac; case "$GRACE" in ''|*[!0-9]*) GRACE=45;; esac
 log "Daemon started; waiting for boot completion"
 while [ "$(prop sys.boot_completed)" != 1 ]; do sleep 2; done
 failures=0
 while :; do
  if data=$(fetch_registry 2>/dev/null); then
   failures=0
   for letter in c d e f g h i j k l m n o p q r s t u v w x y z; do
    enabled=$(json_bool "$data" "$letter"); rawlabel=$(json_label "$data" "$letter")
    upper=$(printf '%s' "$letter" | tr '[:lower:]' '[:upper:]'); label=$(clean_label "$rawlabel" "$upper"); target="/data/media/0/$label"
     prev=$(state_get "$letter")
     case "$enabled" in
      true)
       if [ -n "$prev" ] && [ "$prev" != "$label" ]; then unmount_drive "/data/media/0/$prev"; state_del "$letter"; fi
       mount_drive "$letter" "$label" && state_set "$letter" "$label"
       ;;
      false)
       if [ -n "$prev" ]; then unmount_drive "/data/media/0/$prev"; else unmount_drive "$target"; fi
       state_del "$letter"
       ;;
      *) :;;
     esac
   done
   [ -r "$STATE" ] && cp "$STATE" "$STATE.scan" 2>/dev/null
   while IFS='=' read -r gone glabel; do
    [ -n "$gone" ] || continue
    [ -n "$(json_obj "$data" "$gone")" ] && continue
    if [ -n "$glabel" ]; then unmount_drive "/data/media/0/$glabel"; state_del "$gone"; fi
   done < "$STATE.scan" 2>/dev/null
   rm -f "$STATE.scan" 2>/dev/null
  else
   failures=$((failures + POLL)); log "Registry fetch failed; outage=${failures}s"
   if [ "$failures" -ge "$GRACE" ]; then log "Registry grace exceeded; retaining mounts to avoid detaching unrelated paths"; failures=0; fi
  fi
  sleep "$POLL"
 done
}
main "$@"
