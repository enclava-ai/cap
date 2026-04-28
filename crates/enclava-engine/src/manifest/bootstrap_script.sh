#!/bin/sh
set -eu

if [ "${1:-}" = "--" ]; then
  shift
fi

if [ "$#" -eq 0 ]; then
  echo "secure-pv: no application command provided" >&2
  exit 1
fi

OWNERSHIP_MODE="${STORAGE_OWNERSHIP_MODE:-legacy}"

# Guard: NEVER allow reset-on-mismatch in ownership mode (Pitfall 6 from RESEARCH.md)
# This flag is designed for TLS cert storage (ephemeral, regenerable).
# In ownership mode, a "mismatch" means wrong password -- resetting would destroy user data.
if [ "$OWNERSHIP_MODE" = "level1" ] && [ "${SECURE_PV_RESET_ON_KEY_MISMATCH:-false}" = "true" ]; then
  echo "secure-pv: WARNING: RESET_ON_KEY_MISMATCH forced to 'false' in ownership mode (data protection)" >&2
  export SECURE_PV_RESET_ON_KEY_MISMATCH="false"
fi

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

ensure_secure_pv_tools() {
  if command -v cryptsetup >/dev/null 2>&1 && command -v mkfs.ext4 >/dev/null 2>&1; then
    return 0
  fi
  echo "secure-pv: required tools missing (cryptsetup, mkfs.ext4). Build them into the image." >&2
  return 1
}

ensure_kbs_fetch_tool() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    return 0
  fi
  echo "secure-pv: required KBS fetch tool missing (curl, wget, or python). Build one into the image." >&2
  return 1
}

# Wait for attestation-proxy /health when KBS_CDH_ENDPOINT uses the sidecar (port 8081).
# Avoids a bootstrap race where the workload curls CDH before the proxy has bound its socket.
# Locked owner storage returns 423, but TLS CDH is intentionally available while locked.
wait_for_kbs_proxy_health() {
  WAIT_MAX="${KBS_PROXY_HEALTH_WAIT_SECONDS:-}"
  if [ -z "$WAIT_MAX" ]; then
    case "${KBS_CDH_ENDPOINT:-}" in
      *:8081/*|*:8081)
        WAIT_MAX=300
        ;;
      *)
        WAIT_MAX=0
        ;;
    esac
  fi
  if ! is_uint "$WAIT_MAX" || [ "$WAIT_MAX" -eq 0 ]; then
    return 0
  fi

  CDH="${KBS_CDH_ENDPOINT:-http://127.0.0.1:8081/cdh/resource}"
  HEALTH="${ATTESTATION_PROXY_HEALTH_URL:-}"
  if [ -z "$HEALTH" ]; then
    HEALTH=$(echo "$CDH" | sed 's|/*cdh/resource/*$||')
    HEALTH="${HEALTH}/health"
  fi

  POLL="${KBS_PROXY_HEALTH_POLL_SECONDS:-2}"
  if ! is_uint "$POLL" || [ "$POLL" -eq 0 ]; then
    POLL=2
  fi

  ELAPSED=0
  echo "secure-pv: waiting for KBS attestation-proxy (${HEALTH}, up to ${WAIT_MAX}s)" >&2
  while [ "$ELAPSED" -lt "$WAIT_MAX" ]; do
    if command -v curl >/dev/null 2>&1; then
      HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 5 "$HEALTH" 2>/dev/null || true)"
      if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "423" ]; then
        echo "secure-pv: KBS proxy ready after ${ELAPSED}s" >&2
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      WGET_OUTPUT="$(wget -S --timeout=5 -O /dev/null "$HEALTH" 2>&1 || true)"
      case "$WGET_OUTPUT" in
        *" 200 "*|*" 423 "*)
        echo "secure-pv: KBS proxy ready after ${ELAPSED}s" >&2
        return 0
          ;;
      esac
    else
      echo "secure-pv: curl or wget required to wait for KBS proxy" >&2
      return 1
    fi
    sleep "$POLL"
    ELAPSED=$((ELAPSED + POLL))
  done
  echo "secure-pv: timed out after ${WAIT_MAX}s waiting for ${HEALTH} (is attestation-proxy running?)" >&2
  return 1
}

fetch_kbs_workload_key() {
  BASE="${KBS_CDH_ENDPOINT:-http://127.0.0.1:8081/cdh/resource}"
  RES="${KBS_RESOURCE_PATH:-}"
  OUT="${WORKLOAD_SECRET_PATH:-/run/secure-pv/workload-secret-seed}"
  RETRIES="${KBS_FETCH_RETRIES:-120}"
  SLEEP_SECS="${KBS_FETCH_RETRY_SLEEP_SECONDS:-2}"
  MAX_SLEEP="${KBS_FETCH_MAX_SLEEP_SECONDS:-10}"

  if [ -z "$RES" ]; then
    echo "secure-pv: KBS resource path is empty (set KBS_RESOURCE_PATH)" >&2
    return 1
  fi

  ensure_kbs_fetch_tool
  wait_for_kbs_proxy_health || return 1
  mkdir -p "$(dirname "$OUT")"
  URL="${BASE%/}/${RES}"

  attempt=1
  while [ "$attempt" -le "$RETRIES" ]; do
    if command -v curl >/dev/null 2>&1; then
      HTTP_CODE="$(curl -sS --connect-timeout 5 --max-time 45 -o "$OUT" -w "%{http_code}" "$URL" || true)"
      if [ "$HTTP_CODE" = "200" ] && [ -s "$OUT" ]; then
        chmod 0400 "$OUT"
        echo "$OUT"
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q -T 45 -O "$OUT" "$URL" && [ -s "$OUT" ]; then
        chmod 0400 "$OUT"
        echo "$OUT"
        return 0
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if python3 - "$URL" "$OUT" <<'PY'
import sys
import urllib.request

url = sys.argv[1]
out = sys.argv[2]
try:
  with urllib.request.urlopen(url, timeout=45) as resp:
    if getattr(resp, "status", None) != 200:
      raise RuntimeError("non-200 response")
    data = resp.read()
  if not data:
    raise RuntimeError("empty response")
  with open(out, "wb") as f:
    f.write(data)
except Exception:
  raise SystemExit(1)
raise SystemExit(0)
PY
      then
        chmod 0400 "$OUT"
        echo "$OUT"
        return 0
      fi
    elif command -v python >/dev/null 2>&1; then
      if python - "$URL" "$OUT" <<'PY'
import sys
import urllib.request

url = sys.argv[1]
out = sys.argv[2]
try:
  with urllib.request.urlopen(url, timeout=45) as resp:
    if getattr(resp, "status", None) != 200:
      raise RuntimeError("non-200 response")
    data = resp.read()
  if not data:
    raise RuntimeError("empty response")
  with open(out, "wb") as f:
    f.write(data)
except Exception:
  raise SystemExit(1)
raise SystemExit(0)
PY
      then
        chmod 0400 "$OUT"
        echo "$OUT"
        return 0
      fi
    fi

    sleep "$SLEEP_SECS"
    if [ "$SLEEP_SECS" -lt "$MAX_SLEEP" ]; then
      SLEEP_SECS=$((SLEEP_SECS * 2))
      if [ "$SLEEP_SECS" -gt "$MAX_SLEEP" ]; then
        SLEEP_SECS="$MAX_SLEEP"
      fi
    fi
    attempt=$((attempt + 1))
  done

  echo "secure-pv: failed to fetch workload key from KBS after $RETRIES attempts: $URL" >&2
  return 1
}

shred_key_file() {
  KEY_PATH="$1"
  if [ -n "$KEY_PATH" ] && [ -f "$KEY_PATH" ]; then
    dd if=/dev/urandom bs=32 count=1 conv=notrunc of="$KEY_PATH" status=none 2>/dev/null || true
    rm -f "$KEY_PATH" || true
  fi
}

detect_luks_state() {
  DEV_PATH="$1"
  if cryptsetup isLuks "$DEV_PATH" >/dev/null 2>&1; then
    echo "luks"
    return 0
  fi

  # "LUKS" header magic encoded as hex bytes.
  MAGIC_HEX="$(dd if="$DEV_PATH" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  if [ "$MAGIC_HEX" = "4c554b53" ]; then
    echo "corrupt"
  else
    echo "empty"
  fi
  return 0
}

validate_luks2_header_jq() {
  DEV_PATH="$1"
  METADATA="$(cryptsetup luksDump --dump-json-metadata "$DEV_PATH" 2>/dev/null)" || return 1

  if command -v jq >/dev/null 2>&1; then
    echo "$METADATA" | jq -e '
      ((.segments | type) == "object") and
      ((.keyslots | type) == "object") and
      ((.segments | length) > 0) and
      ((.keyslots | length) > 0) and
      ([.segments[]? | .encryption // ""] | all(. == "aes-xts-plain64")) and
      ([.keyslots[]? | .area.encryption // ""] | all((ascii_downcase | contains("null") | not)))
    ' >/dev/null 2>&1
    return $?
  fi

  if command -v python3 >/dev/null 2>&1; then
    echo "$METADATA" | python3 -c 'import json,sys; doc=json.load(sys.stdin); segments=doc.get("segments"); keyslots=doc.get("keyslots"); ok=isinstance(segments,dict) and bool(segments) and isinstance(keyslots,dict) and bool(keyslots) and all((seg or {}).get("encryption","")=="aes-xts-plain64" for seg in segments.values()) and all("null" not in (((slot or {}).get("area") or {}).get("encryption","")).lower() for slot in keyslots.values()); raise SystemExit(0 if ok else 1)' >/dev/null 2>&1
    return $?
  fi

  if command -v python >/dev/null 2>&1; then
    echo "$METADATA" | python -c 'import json,sys; doc=json.load(sys.stdin); segments=doc.get("segments"); keyslots=doc.get("keyslots"); ok=isinstance(segments,dict) and bool(segments) and isinstance(keyslots,dict) and bool(keyslots) and all((seg or {}).get("encryption","")=="aes-xts-plain64" for seg in segments.values()) and all("null" not in (((slot or {}).get("area") or {}).get("encryption","")).lower() for slot in keyslots.values()); raise SystemExit(0 if ok else 1)' >/dev/null 2>&1
    return $?
  fi

  echo "secure-pv: skipping LUKS2 metadata validation; jq/python unavailable" >&2
  return 0
}

ownership_fatal() {
  ERROR_FILE="$1"
  KEY_FILE="$2"
  MESSAGE="$3"
  printf '%s\n' "$MESSAGE" > "$ERROR_FILE"
  shred_key_file "$KEY_FILE"
  return 1
}

format_and_open_device() {
  DEV_PATH="$1"
  MAP_NAME="$2"
  KEY_PATH="$3"
  ERROR_FILE="$4"

  if ! cryptsetup luksFormat "$DEV_PATH" --key-file "$KEY_PATH" \
    --type luks2 --cipher aes-xts-plain64 --key-size 512 --integrity hmac-sha256 --batch-mode; then
    ownership_fatal "$ERROR_FILE" "$KEY_PATH" "format_failed"
    return 1
  fi

  if ! cryptsetup luksOpen "$DEV_PATH" "$MAP_NAME" --key-file "$KEY_PATH"; then
    ownership_fatal "$ERROR_FILE" "$KEY_PATH" "luks_open_after_format_failed"
    return 1
  fi

  if ! mkfs.ext4 -F "/dev/mapper/$MAP_NAME"; then
    ownership_fatal "$ERROR_FILE" "$KEY_PATH" "mkfs_failed"
    return 1
  fi

  return 0
}

wait_for_handoff_key() {
  KEY_FILE="$1"
  TIMEOUT="${OWNERSHIP_KEY_WAIT_TIMEOUT_SECONDS:-600}"
  ELAPSED=0

  while [ ! -f "$KEY_FILE" ]; do
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      return 1
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
  done
  return 0
}

wait_for_proxy_error_cleanup() {
  ERROR_FILE="$1"
  while [ -f "$ERROR_FILE" ]; do
    sleep 1
  done
  return 0
}

ownership_bootstrap() {
  DEV="${CRYPTSETUP_DEVICE:-/dev/csi0}"
  MNT="${VOLUME_MOUNT_POINT:-/app/data}"
  MAP="${LUKS_MAPPING_NAME:-secure-pv}"
  SLOT_NAME="${OWNERSHIP_SLOT:-app-data}"
  if [ "$OWNERSHIP_MODE" = "password" ] || [ "$OWNERSHIP_MODE" = "auto-unlock" ]; then
    SIGNAL_ROOT_DEFAULT="/run/ownership-signal/${SLOT_NAME}"
  else
    SIGNAL_ROOT_DEFAULT="/run/ownership-signal"
  fi
  KEY_FILE="${OWNERSHIP_KEY_FILE:-${SIGNAL_ROOT_DEFAULT}/key}"
  ERROR_FILE="${OWNERSHIP_ERROR_FILE:-${SIGNAL_ROOT_DEFAULT}/error}"
  UNLOCKED_FILE="${OWNERSHIP_UNLOCKED_FILE:-${SIGNAL_ROOT_DEFAULT}/unlocked}"
  SIGNAL_DIR="$(dirname "$KEY_FILE")"

  if [ ! -b "$DEV" ]; then
    echo "secure-pv: block device missing: $DEV" >&2
    return 1
  fi

  ensure_secure_pv_tools || return 1
  mkdir -p "$SIGNAL_DIR"
  chmod 2770 "$SIGNAL_DIR" || true
  rm -f "$UNLOCKED_FILE" "$ERROR_FILE" || true

  if cryptsetup status "$MAP" >/dev/null 2>&1; then
    cryptsetup luksClose "$MAP" || true
  fi

  while true; do
    if ! wait_for_handoff_key "$KEY_FILE"; then
      ownership_fatal "$ERROR_FILE" "$KEY_FILE" "unlock_timeout"
      return 1
    fi

    LUKS_STATE="$(detect_luks_state "$DEV")"
    case "$LUKS_STATE" in
      luks)
        if ! validate_luks2_header_jq "$DEV"; then
          ownership_fatal "$ERROR_FILE" "$KEY_FILE" "luks_header_validation_failed"
          return 1
        fi
        if ! cryptsetup luksOpen "$DEV" "$MAP" --key-file "$KEY_FILE"; then
          if [ "$OWNERSHIP_MODE" = "level1" ]; then
            printf '%s\n' "wrong_password" > "$ERROR_FILE"
            shred_key_file "$KEY_FILE"
            wait_for_proxy_error_cleanup "$ERROR_FILE"
            continue
          fi
          if [ "${ENCLAVA_SECURE_PV_BOOTSTRAP:-0}" = "1" ] && [ "${SECURE_PV_RESET_ON_KEY_MISMATCH:-false}" = "true" ]; then
            echo "secure-pv: ownership key mismatch detected; resetting LUKS header in bootstrap mode" >&2
            dd if=/dev/zero of="$DEV" bs=1M count=64 conv=fsync || true
            if ! format_and_open_device "$DEV" "$MAP" "$KEY_FILE" "$ERROR_FILE"; then
              return 1
            fi
          else
          ownership_fatal "$ERROR_FILE" "$KEY_FILE" "luks_open_failed"
          return 1
          fi
        fi
        ;;
      corrupt)
        ownership_fatal "$ERROR_FILE" "$KEY_FILE" "luks_header_corrupt"
        return 1
        ;;
      empty)
        if ! format_and_open_device "$DEV" "$MAP" "$KEY_FILE" "$ERROR_FILE"; then
          return 1
        fi
        ;;
      *)
        ownership_fatal "$ERROR_FILE" "$KEY_FILE" "unknown_luks_state"
        return 1
        ;;
    esac

    shred_key_file "$KEY_FILE"
    mkdir -p "$MNT"
    if mountpoint -q "$MNT" 2>/dev/null; then
      umount "$MNT" || true
    fi
    if ! mount "/dev/mapper/$MAP" "$MNT"; then
      ownership_fatal "$ERROR_FILE" "$KEY_FILE" "mount_failed"
      return 1
    fi

    printf 'unlocked_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$UNLOCKED_FILE"
    return 0
  done
}

resolve_workload_key_path() {
  SOURCE="${WORKLOAD_SECRET_SOURCE:-secret}"
  case "$SOURCE" in
    secret)
      echo "${WORKLOAD_SECRET_PATH:-/enclave/secrets/workload-secret-seed}"
      return 0
      ;;
    kbs)
      fetch_kbs_workload_key
      return $?
      ;;
    *)
      echo "secure-pv: unsupported workload key source: $SOURCE" >&2
      return 1
      ;;
  esac
}

secure_pv_bootstrap() {
  DEV="${CRYPTSETUP_DEVICE:-/dev/csi0}"
  MNT="${VOLUME_MOUNT_POINT:-/app/data}"

  # In ownership mode, consume the handoff files directly and run LUKS operations here.
  if [ "$OWNERSHIP_MODE" = "level1" ] || [ "$OWNERSHIP_MODE" = "password" ] || [ "$OWNERSHIP_MODE" = "auto-unlock" ]; then
    ownership_bootstrap || return 1
    return 0
  fi

  KEY="$(resolve_workload_key_path)"
  MAP="${LUKS_MAPPING_NAME:-secure-pv}"
  LUKS_INTEGRITY="${SECURE_PV_LUKS_INTEGRITY:-hmac-sha256}"
  RESET_ON_KEY_MISMATCH="${SECURE_PV_RESET_ON_KEY_MISMATCH:-false}"

  if [ ! -b "$DEV" ]; then
    echo "secure-pv: block device missing: $DEV" >&2
    return 1
  fi
  if [ -z "$KEY" ] || [ ! -f "$KEY" ]; then
    echo "secure-pv: workload key missing: $KEY" >&2
    return 1
  fi

  ensure_secure_pv_tools

  if cryptsetup status "$MAP" >/dev/null 2>&1; then
    cryptsetup luksClose "$MAP" || true
  fi

  if ! cryptsetup isLuks "$DEV" >/dev/null 2>&1; then
    cryptsetup luksFormat "$DEV" "$KEY" --batch-mode --type luks2 --integrity "$LUKS_INTEGRITY"
  fi

  if ! cryptsetup luksOpen "$DEV" "$MAP" --key-file "$KEY"; then
    if [ "${ENCLAVA_SECURE_PV_BOOTSTRAP:-0}" = "1" ] && [ "$RESET_ON_KEY_MISMATCH" = "true" ]; then
      echo "secure-pv: key mismatch detected; resetting LUKS header in bootstrap mode" >&2
      dd if=/dev/zero of="$DEV" bs=1M count=64 conv=fsync || true
      cryptsetup luksFormat "$DEV" "$KEY" --batch-mode --type luks2 --integrity "$LUKS_INTEGRITY"
      cryptsetup luksOpen "$DEV" "$MAP" --key-file "$KEY"
    else
      echo "secure-pv: key mismatch detected; refusing destructive reset (set SECURE_PV_RESET_ON_KEY_MISMATCH=true to force reset)" >&2
      return 1
    fi
  fi

  if [ "${WORKLOAD_SECRET_SOURCE:-secret}" = "kbs" ] && [ -f "$KEY" ]; then
    chmod 000 "$KEY" || true
    if command -v shred >/dev/null 2>&1; then
      shred -u "$KEY" 2>/dev/null || rm -f "$KEY" || true
    else
      rm -f "$KEY" || true
    fi
  elif [ "${WORKLOAD_SECRET_SOURCE:-secret}" = "secret" ] && [ -f "$KEY" ]; then
    chmod 000 "$KEY" || true
    umount /enclave/secrets 2>/dev/null || true
  fi

  TYPE_LINE="$(blkid "/dev/mapper/$MAP" 2>/dev/null || true)"
  if ! printf '%s' "$TYPE_LINE" | grep -q 'TYPE="ext4"'; then
    mkfs.ext4 -F "/dev/mapper/$MAP"
  fi

  mkdir -p "$MNT"
  if mountpoint -q "$MNT" 2>/dev/null; then
    umount "$MNT" || true
  fi
  mount "/dev/mapper/$MAP" "$MNT"

  BIND_SPECS="${SECURE_PV_BIND_MOUNTS:-}"
  if [ -n "$BIND_SPECS" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for spec in $BIND_SPECS; do
      IFS="$OLD_IFS"
      SRC="${spec%%:*}"
      DST="${spec#*:}"
      if [ -z "$SRC" ] || [ -z "$DST" ] || [ "$SRC" = "$DST" ]; then
        IFS=','
        continue
      fi
      mkdir -p "$SRC" "$DST"
      if mountpoint -q "$DST" 2>/dev/null; then
        umount "$DST" || true
      fi
      mount --bind "$SRC" "$DST"
      IFS=','
    done
    IFS="$OLD_IFS"
  fi

  SENTINEL="${MNT%/}/.persist-sentinel"
  if [ ! -f "$SENTINEL" ]; then
    date -u > "$SENTINEL"
    sync
  fi

  TEST_FILE="${MNT%/}/.secure-pv-write-test.$$"
  echo "secure-pv write test $(date -u)" > "$TEST_FILE"
  sync
  rm -f "$TEST_FILE"
  sync
}

resolve_exec_identity() {
  TARGET="$1"
  SECURE_PV_EXEC_IDENTITY_KIND="named"
  if id "$TARGET" >/dev/null 2>&1; then
    SECURE_PV_EXEC_UID="$(id -u "$TARGET")"
    SECURE_PV_EXEC_GID="$(id -g "$TARGET")"
    export SECURE_PV_EXEC_UID SECURE_PV_EXEC_GID SECURE_PV_EXEC_IDENTITY_KIND
    return 0
  fi

  if [ "${TARGET#*:}" != "$TARGET" ]; then
    UID_PART="${TARGET%%:*}"
    GID_PART="${TARGET##*:}"
  else
    UID_PART="$TARGET"
    GID_PART="$TARGET"
  fi

  if ! is_uint "$UID_PART" || ! is_uint "$GID_PART"; then
    return 1
  fi

  SECURE_PV_EXEC_UID="$UID_PART"
  SECURE_PV_EXEC_GID="$GID_PART"
  SECURE_PV_EXEC_IDENTITY_KIND="numeric"
  export SECURE_PV_EXEC_UID SECURE_PV_EXEC_GID SECURE_PV_EXEC_IDENTITY_KIND
  return 0
}

maybe_chown_mount_for_exec_identity() {
  MNT="${VOLUME_MOUNT_POINT:-/app/data}"
  if [ ! -d "$MNT" ]; then
    return 0
  fi
  if [ "${SECURE_PV_CHOWN_RECURSIVE:-false}" = "true" ]; then
    chown -R "${SECURE_PV_EXEC_UID}:${SECURE_PV_EXEC_GID}" "$MNT"
  else
    chown "${SECURE_PV_EXEC_UID}:${SECURE_PV_EXEC_GID}" "$MNT"
  fi
}

secure_pv_bootstrap

if [ -n "${SECURE_PV_EXEC_AS:-}" ]; then
  if ! resolve_exec_identity "${SECURE_PV_EXEC_AS}"; then
    echo "secure-pv: invalid SECURE_PV_EXEC_AS identity: ${SECURE_PV_EXEC_AS}" >&2
    exit 1
  fi

  maybe_chown_mount_for_exec_identity

  if command -v setpriv >/dev/null 2>&1; then
    STRIP_CAPS="${SECURE_PV_STRIP_RUNTIME_CAPS:-true}"
    if [ "$STRIP_CAPS" = "true" ]; then
      if setpriv --help 2>&1 | grep -q -- '--ambient-caps'; then
        exec setpriv --reuid "$SECURE_PV_EXEC_UID" --regid "$SECURE_PV_EXEC_GID" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
      elif setpriv --help 2>&1 | grep -q -- '--inh-caps'; then
        exec setpriv --reuid "$SECURE_PV_EXEC_UID" --regid "$SECURE_PV_EXEC_GID" --clear-groups --no-new-privs --bounding-set=-all --inh-caps=-all -- "$@"
      elif setpriv --help 2>&1 | grep -q -- '--bounding-set'; then
        exec setpriv --reuid "$SECURE_PV_EXEC_UID" --regid "$SECURE_PV_EXEC_GID" --clear-groups --no-new-privs --bounding-set=-all -- "$@"
      fi
    fi
    exec setpriv --reuid "$SECURE_PV_EXEC_UID" --regid "$SECURE_PV_EXEC_GID" --clear-groups --no-new-privs -- "$@"
  fi

  if [ "$SECURE_PV_EXEC_IDENTITY_KIND" = "named" ]; then
    if command -v gosu >/dev/null 2>&1; then
      exec gosu "$SECURE_PV_EXEC_AS" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
      exec su-exec "$SECURE_PV_EXEC_AS" "$@"
    elif command -v runuser >/dev/null 2>&1; then
      exec runuser -u "$SECURE_PV_EXEC_AS" -- "$@"
    fi
  fi

  echo "secure-pv: SECURE_PV_EXEC_AS requested but no supported user switch helper found; refusing to continue as root" >&2
  exit 1
fi

exec "$@"
