# Hermes XMPP: Verifying and Trusting a New OMEMO Device

Companion: [OMEMO fingerprints and trust guide](omemo-fingerprints-and-trust-guide.md).
All JIDs below are examples; replace `alice@example.org` with the contact's
actual bare JID (without a resource).

## Scope and Security Preconditions

This procedure changes trust for a contact's device. It does not register a new
Hermes identity or add a contact to the gateway's user allow-list.

The repository adapter defaults to OMEMO enabled and strict direct-message
trust, with Blind Trust Before Verification (BTBV) off. Explicit `TRUSTED`
decisions remain effective. With BTBV off, the dependency treats
`BLINDLY_TRUSTED` as undecided; outbound manual-trust handling can mark undecided
devices `DISTRUSTED`. Incoming direct messages require effective device trust,
not just successful decryption. Use `TRUSTED` only after independent verification.

See the [OMEMO security policy](../README.md#omemo-security-policy) for the
enforcement scope and opt-outs. Confirm the deployed adapter and effective
configuration match it before testing. In particular, keep `XMPP_OMEMO_BTBV`
off and OMEMO enabled for this procedure. TLS alone does not protect message
content from the server. Do not send sensitive discovery or test content.

The companion guide records the dependency versions checked for the flat store
layout, URL-safe Base64 Ed25519 identity keys and textual trust grades. Check
your installed versions before applying the scripts; do not assume every
deployment uses the same representation.

## Execution Environment

**Illustrative deployment assumptions, not repository defaults:** this repository
ships no Compose stack. The commands below assume your own `compose.yaml`, a
service named `hermes`, Python 3, a persistent data volume and store-owner UID
10000. Run Docker commands **on the host**, in your stack's directory, only after
checking the actual service, mounts, interpreter, UID/GID and paths. Substitute
your values in every command and script.

- Example store inside the container: `/opt/data/xmpp_omemo.json`.
- Example installed adapter: `/opt/data/plugins/hermes-xmpp-plugin/adapter.py`.
- Example gateway log: `/opt/data/logs/gateway.log`.
- The adapter default is `xmpp_omemo.json` under the resolved Hermes home, not
  `/opt/data`. Check nested `omemo.storage_path`, flat `omemo_storage_path` and
  `XMPP_OMEMO_STORAGE_PATH`, as well as the actual persistent mount.
- Stop all other processes or containers that write this same store, including
  one-shot senders. Stopping the gateway alone does not stop external writers.

## 1. Discover the Device Identity

Have the contact send a non-sensitive test message from the new device. The
adapter may discover and record its identity during OMEMO processing. Under the
default strict policy, an untrusted device's direct message is not dispatched
to Hermes even if decryption succeeds.

Do not assume that a refused message necessarily created a store entry. Inspect
the store and logs. If the identity is missing, investigate device publication,
the allow-list, and OMEMO initialization instead of inventing a trust entry.

Legacy Axolotl bundles publish X25519 identity keys. The conversion from an
Ed25519 public key loses a sign bit, so the original Ed25519 encoding cannot be
uniquely recovered from that X25519 value alone. This is not a claim that a
private key is required to construct possible Edwards counterparts. Use the
identity encoding actually recorded by the adapter.

## 2. Stop Writers and List Candidates

The repository adapter keeps the store in memory and rewrites the
JSON file non-atomically on each storage update, not necessarily once per
message. A live edit can be overwritten, and a concurrent read can encounter
incomplete JSON. Stop the container before inspecting or modifying the store:

```bash
docker compose stop hermes
docker compose ps --all hermes
```

Confirm that the container is stopped and that no other writer uses its store.
Then use a temporary maintenance container with the same persistent volume:

```bash
docker compose run --rm --no-deps -T --user 10000 --entrypoint python3 hermes - <<'PY'
import base64
import json

JID = "alice@example.org"
P = 2**255 - 19


def fingerprint(key):
    ed = base64.b64decode(key + "=" * (-len(key) % 4),
                         altchars=b"-_", validate=True)
    if len(ed) != 32:
        raise ValueError("Expected a 32-byte Ed25519 public key")
    y = int.from_bytes(ed, "little") & ((1 << 255) - 1)
    if y >= P or y == 1:
        raise ValueError("Non-canonical or non-convertible Ed25519 key")
    u = (1 + y) * pow(1 - y, P - 2, P) % P
    value = u.to_bytes(32, "little").hex().upper()
    return " ".join(value[i:i + 8] for i in range(0, 64, 8))


with open("/opt/data/xmpp_omemo.json", encoding="utf-8") as file:
    store = json.load(file)

prefix = f"/devices/{JID}/"
for path, key in sorted(store.items()):
    if path.startswith(prefix) and path.endswith("/identity_key"):
        device_id = path[len(prefix):-len("/identity_key")]
        trust = store.get(f"/trust/{JID}/{key}", "MISSING")
        print(device_id, trust, key, fingerprint(key))
PY
```

As in the companion guide, the formula assumes valid curve points from the
local store; it is not full validation of untrusted Ed25519 keys.

Compare with the currently published server device list using an independent
XMPP client. A local identity absent from the list is not automatically a
harmless "ghost": investigate stale publication, removal, replacement, or
compromise. Do not trust the server list as proof of device ownership.

## 3. Verify the Fingerprint

Ask the contact to read the new device's **own** fingerprint in its client.
Compare it through an independent authenticated channel, such as an in-person
comparison or a previously verified device. A fingerprint asserted only by the
unverified new device is not sufficient.

After ignoring presentation-only spaces and letter case, all 64 hexadecimal
characters must match the candidate's derived fingerprint. Also confirm the
intended JID and device ID. If anything differs, do not grant trust.

## 4. Back Up and Update the Existing Entry

Keep the main container stopped. Replace both example placeholders below with
the verified candidate's values. The script refuses missing device or trust
entries, backs up the complete store, and preserves file ownership and mode.
The maintenance user must match the store owner; UID 10000 is only the example
deployment assumption above. If the checks fail, investigate ownership rather than relaxing
permissions or blindly running the command as root.

```bash
docker compose run --rm --no-deps -T --user 10000 --entrypoint python3 hermes - <<'PY'
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

p = Path("/opt/data/xmpp_omemo.json")
JID = "alice@example.org"
KEY = "<verified_identity_key_b64>"
DEVICE_ID = "<verified_device_id>"
GRADE = "TRUSTED"

info = p.stat()
if info.st_uid != os.geteuid():
    raise RuntimeError("Run as the store owner")
with p.open(encoding="utf-8") as file:
    store = json.load(file)

path = f"/trust/{JID}/{KEY}"
device_path = f"/devices/{JID}/{DEVICE_ID}/identity_key"
if path not in store or store.get(device_path) != KEY:
    raise ValueError("Candidate does not match an existing device and trust entry")
if GRADE not in {"TRUSTED", "DISTRUSTED"}:
    raise ValueError("Unsupported grade for this procedure")

# mkstemp creates unique, private files in the same directory as the store.
fd, backup = tempfile.mkstemp(prefix=p.name + ".backup-", dir=p.parent)
os.close(fd)
shutil.copy2(p, backup)
print("Backup:", backup)

store[path] = GRADE
fd, temporary = tempfile.mkstemp(prefix=p.name + ".tmp-", dir=p.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        os.fchown(file.fileno(), info.st_uid, info.st_gid)
        os.fchmod(file.fileno(), stat.S_IMODE(info.st_mode))
        json.dump(store, file, indent=2)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, p)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print("Updated:", path, "->", GRADE)
PY
```

The replacement is atomic on the same filesystem, avoiding a partially written
JSON file. It is not a complete power-loss durability guarantee and does not
preserve custom ACLs or extended attributes. If your store uses those, use a
maintenance method that preserves them. Protect backups: they contain the
entire OMEMO store, including secret material. Retain them only as needed.

## 5. Restart and Verify Both Directions

Only after the update succeeds:

```bash
docker compose up -d hermes
docker compose exec hermes tail -n 100 -f /opt/data/logs/gateway.log
```

Have the contact send another non-sensitive OMEMO message from the new device,
then check the reply on that device. Verify that both messages were actually
OMEMO-encrypted and decrypted, not merely delivered. The repository adapter
refuses outbound direct-message plaintext fallback while OMEMO is enabled.
Check new logs for trust/decryption failures and refused encryption. Existing
historical warnings or warnings about other devices do not by themselves mean
that this update failed.

Also test separately that an
unverified device and ordinary plaintext messages are handled according to
that policy. Absence of a log warning is not proof of encryption enforcement.

## Rollback and Lockout

To revoke this trust decision, stop all writers again and repeat step 4 with
`GRADE = "DISTRUSTED"`, then restart. Previously delivered or queued messages
cannot be recalled. Verify the installed adapter's behavior for subsequent
messages; revocation is not an instantaneous undo of earlier encryption.

For lockout, use authenticated host/container administration to repair the
verified trust entry. `XMPP_REQUIRE_OMEMO_INBOUND=0` is supported, but only
allows authorized plaintext direct input while OMEMO remains enabled. It does
not repair device trust or failed decryption, and does not relax outbound
encryption. It exposes unauthenticated input to server injection; do not use it
as a trust-repair procedure.

## Implementation Reference

[Repository adapter](../adapter.py) and
[security policy](../README.md#omemo-security-policy).
The deployed persistent-volume plugin and dependency versions may differ.
This runbook was reviewed against repository code and the installed dependency
sources identified in the companion guide. Its fingerprint calculation was
checked read-only; the maintenance/update commands have not been executed
against a live Hermes deployment or real store.
