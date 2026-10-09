#!/system/bin/sh
# WSA WebDAV drive reconciler; requires a functional webdavfs binary and FUSE.
# On Windows after WSA startup: adb reverse tcp:8085 tcp:8085
TAG='[WebDAV]'; CONF='/data/adb/webdavfs.conf'; REGISTRY='http://127.0.0.1:8085/info.json'
LOG='/data/adb/lsp-boot.log'; APPLOG='/storage/emulated/0/WSA Installer/post-fs-data.log'
PIDFILE='/data/adb/webdavfs-daemon.pid'; BIN='/data/adb/webdavfs'
POLL=3; GRACE=45; USER=''; PASS=''; SSL_VERIFY=0
MOUNT_OPTS='allow_other,context=u:object_r:media_rw_data_file:s0'
log(){ line="$TAG $*"; echo "$line" >> "$LOG" 2>/dev/null; echo "$line" >> "$APPLOG" 2>/dev/null; echo "$line"; }
prop(){ getprop "$1" 2>/dev/null; }
fetch_registry(){ if command -v curl >/dev/null 2>&1; then curl -fsS --connect-timeout 2 --max-time 5 "$REGISTRY"; elif command -v wget >/dev/null 2>&1; then wget -q -T 5 -O - "$REGISTRY"; else return 127; fi; }
json_obj(){ echo "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\{[^}]*" | head -n 1; }
json_bool(){ json_obj "$1" "$2" | grep -oE '"mount"[[:space:]]*:[[:space:]]*(true|false)' | head -n 1 | sed -E 's/.*:[[:space:]]*//'; }
json_label(){ json_obj "$1" "$2" | grep -oE '"sdcard"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/^[^"]*"sdcard"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' | head -n 1; }
clean_label(){ label=$(printf '%s' "$1" | tr '/\\' '__' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); case "$label" in ''|.|..) label="$2: Drive";; esac; printf '%s' "$label"; }
mounted(){ grep -F " $1 " /proc/mounts >/dev/null 2>&1; }
mount_drive(){ letter="$1"; label="$2"; target="/data/media/0/$label"; mounted "$target" && return 0; mkdir -p "$target" || { log "ERROR creating $target"; return 1; }; [ -x "$BIN" ] || { log "ERROR missing executable $BIN"; return 1; }; log "Mount request drive=$letter label=$label"; "$BIN" "http://127.0.0.1:8085/$letter/" "$target" -o "$MOUNT_OPTS" >> "$LOG" 2>&1; rc=$?; if [ "$rc" -eq 0 ]; then log "Mount command returned success: $target"; else log "ERROR mount failed drive=$letter exit=$rc"; fi; return "$rc"; }
unmount_drive(){ target="$1"; if mounted "$target"; then if command -v fusermount >/dev/null 2>&1; then fusermount -u "$target"; elif command -v umount >/dev/null 2>&1; then umount "$target"; else return 1; fi; log "Unmounted $target"; fi; }
main(){
 umask 077; mkdir -p /data/adb
 if [ -r "$CONF" ]; then . "$CONF"; fi
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
    case "$enabled" in true) mount_drive "$letter" "$label";; false) unmount_drive "$target";; *) :;; esac
   done
  else
   failures=$((failures + POLL)); log "Registry fetch failed; outage=${failures}s"
   if [ "$failures" -ge "$GRACE" ]; then log "Registry grace exceeded; retaining mounts to avoid detaching unrelated paths"; failures=0; fi
  fi
  sleep "$POLL"
 done
}
main "$@"
