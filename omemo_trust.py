"""Offline maintenance of the adapter's flat OMEMO JSON store."""

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


TRUST_LEVELS = {"TRUSTED", "DISTRUSTED", "UNDECIDED", "BLINDLY_TRUSTED"}
OFFLINE_WARNING = (
    "Stop ALL writers (gateway, other profiles, containers and one-shot senders). "
    "The adapter caches this store in memory and can overwrite edits. "
    "This tool cannot detect all writers; --offline acknowledges they are stopped."
)


def default_store():
    override = os.environ.get("XMPP_OMEMO_STORAGE_PATH")
    if override:
        return Path(override)
    try:
        from hermes_constants import get_hermes_home
        home = get_hermes_home()
    except Exception:
        home = os.environ.get("HERMES_HOME") or Path.home() / ".hermes"
    return Path(home) / "xmpp_omemo.json"


def jid(value):
    if not value or "/" in value or any(c.isspace() or not c.isprintable() for c in value):
        raise argparse.ArgumentTypeError("expected a bare JID without whitespace or resource")
    return value


def device_id(value):
    if not re.fullmatch(r"[1-9][0-9]*", value) or int(value) > 2**31 - 1:
        raise argparse.ArgumentTypeError("device ID must be a canonical integer from 1 to 2147483647")
    return value


def fingerprint(value):
    """Convert the persisted Ed25519 public identity, never private material."""
    try:
        from xeddsa import ed25519_pub_to_curve25519_pub, XEdDSAException
    except ImportError:
        raise ValueError("XEdDSA is required; install the existing optional OMEMO dependencies") from None
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
        raise ValueError("invalid URL-safe Base64 public identity key")
    try:
        public = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(public).decode().rstrip("=") != value.rstrip("="):
            raise ValueError("non-canonical public identity key")
        return ed25519_pub_to_curve25519_pub(public).hex().upper()
    except (binascii.Error, XEdDSAException, ValueError):
        raise ValueError("invalid or unsuitable Ed25519 public identity key") from None


def verified_fingerprint(value):
    value = value.replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{64}", value):
        raise argparse.ArgumentTypeError("fingerprint must contain exactly 64 hexadecimal characters (spaces allowed)")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in store")
        result[key] = value
    return result


def replace_store(path, raw, store, info):
    if info.st_uid != os.geteuid():
        raise ValueError("run mutations as the store owner")
    # Backups contain the entire secret store: never copy its potentially public mode.
    fd, backup = tempfile.mkstemp(prefix=path.name + ".backup-", dir=path.parent)
    with os.fdopen(fd, "wb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            os.fchown(file.fileno(), info.st_uid, info.st_gid)
            os.fchmod(file.fileno(), stat.S_IMODE(info.st_mode))
            json.dump(store, file, indent=2, allow_nan=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
        ):
            raise ValueError("store changed during maintenance; stop all writers and retry")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=OFFLINE_WARNING)
    parser.add_argument("--store", type=Path, help="store path; otherwise XMPP_OMEMO_STORAGE_PATH or resolved Hermes home")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list public fingerprints and persisted trust; snapshot only")
    listing.add_argument("--jid", type=jid)
    for name in ("trust", "distrust"):
        command = commands.add_parser(name, description=OFFLINE_WARNING)
        command.add_argument("--jid", required=True, type=jid)
        command.add_argument("--device-id", required=True, type=device_id)
        command.add_argument("--offline", required=True, action="store_true", help="acknowledge ALL writers are stopped")
        if name == "trust":
            command.add_argument("--fingerprint", required=True, type=verified_fingerprint,
                                 help="64-hex fingerprint verified through an independent authenticated channel")
    args = parser.parse_args(argv)
    try:
        path = args.store if args.store is not None else default_store()
        if args.command == "list":
            print("Warning: offline snapshot only; live reads may be incomplete or stale. " + OFFLINE_WARNING, file=sys.stderr)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("store must be a regular file, not a symlink")
            raw = file.read()
        store = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON value")))
        if not isinstance(store, dict) or any(not key.startswith("/") for key in store):
            raise ValueError("expected a flat JSON store with absolute key paths")
        devices = {}
        for key, value in store.items():
            if key.startswith("/trust/"):
                parts = key.split("/")
                if len(parts) != 4 or not isinstance(value, str) or value not in TRUST_LEVELS:
                    raise ValueError("invalid persisted trust entry")
                jid(parts[2])
                fingerprint(parts[3])
            if key.startswith("/devices/"):
                parts = key.split("/")
                if len(parts) == 4 and parts[3] == "list":
                    jid(parts[2])
                    if not isinstance(value, list) or any(type(item) is not int for item in value):
                        raise ValueError("invalid device list")
                    for item in value:
                        device_id(str(item))
                    continue
                if len(parts) != 5:
                    raise ValueError("invalid device path")
                jid(parts[2])
                device_id(parts[3])
                if parts[4] == "identity_key":
                    devices[(parts[2], parts[3])] = (value, fingerprint(value))
        if args.command == "list":
            rows = [("JID", "DEVICE_ID", "TRUST", "FINGERPRINT")]
            for (bare, device), (identity, fp) in sorted(
                devices.items(), key=lambda item: (item[0][0], int(item[0][1]))
            ):
                if args.jid is None or args.jid == bare:
                    grade = store.get(f"/trust/{bare}/{identity}", "MISSING")
                    rows.append((bare, device, grade, ' '.join(fp[i:i+8] for i in range(0, 64, 8))))
            widths = [max(len(value) for value in column) for column in zip(*rows)]
            for row in rows:
                print("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())
            return 0
        candidate = devices.get((args.jid, args.device_id))
        if candidate is None:
            raise ValueError("device has no existing recorded identity")
        identity, fp = candidate
        trust_path = f"/trust/{args.jid}/{identity}"
        if args.command == "trust" and fp != args.fingerprint:
            raise ValueError("verified fingerprint does not match the recorded device identity; no changes made")
        grade = "TRUSTED" if args.command == "trust" else "DISTRUSTED"
        store[trust_path] = grade
        backup = replace_store(path, raw, store, info)
        print(f"{args.jid} device {args.device_id}: {grade}\nPrivate backup (contains secrets): {backup}")
        return 0
    except (OSError, ValueError, TypeError, argparse.ArgumentTypeError) as exc:
        # JSON decoding errors can include input; never echo store contents.
        message = "invalid JSON store" if isinstance(exc, (json.JSONDecodeError, UnicodeError)) else str(exc)
        print(f"Error: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
