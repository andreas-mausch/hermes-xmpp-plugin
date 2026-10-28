# Hermes XMPP: Verifying and Trusting a New OMEMO Device

Companion: [OMEMO fingerprints and trust guide](omemo-fingerprints-and-trust-guide.md).
All JIDs, device IDs, paths, UIDs and fingerprints below are examples.

## Scope and Preconditions

This procedure changes an existing device identity's persisted trust. It does
not register an identity or add a contact to the gateway allow-list. The default
policy enables OMEMO, disables Blind Trust Before Verification (BTBV), and
requires effective device trust for incoming direct messages. Outbound manual
trust handling can mark undecided devices `DISTRUSTED`. Grant `TRUSTED` only
after independent verification. Confirm your deployed adapter and configuration
match the [security policy](omemo-fingerprints-and-trust-guide.md#omemo-security-policy).

Use `python -m omemo_trust` from this repository directory, with the same Python
environment and optional OMEMO dependencies as the adapter. The CLI uses
XEdDSA's vetted Ed25519-to-Curve25519 public-key conversion, not handwritten
curve arithmetic. It handles the documented flat JSON store and legacy
fingerprints, not every OMEMO format.

`--store` explicitly selects the store. Otherwise the CLI uses
`XMPP_OMEMO_STORAGE_PATH`, then the resolved Hermes home (Hermes' context-aware
helper when available, otherwise `HERMES_HOME` or `~/.hermes`) plus
`xmpp_omemo.json`. It does not import the adapter, load `.env`, or read nested
`omemo.storage_path` / flat `omemo_storage_path` configuration. Select the actual
profile and configured path explicitly when needed.

## 1. Discover the Identity

Have the contact send a non-sensitive OMEMO test message from the new device.
The dependency records the actual downloaded bundle identity before decryption.
After successful decryption, the adapter persists an `UNDECIDED` decision for
an undecided sender and discards the message until effectively trusted. BTBV
does not automatically approve undecided inbound devices.

A refused message does not guarantee discovery: authorization, initialized
OMEMO, sender publication, downloadable bundles and usable recipient key
material are prerequisites. Failures after discovery may leave an identity
without a trust decision; earlier failures may leave no identity. If missing,
investigate publication, allow-list and initialization; never invent identities.

Use the identity actually recorded by the adapter. Legacy server bundles publish
X25519 keys; converting Ed25519 to X25519 loses a sign bit and is not uniquely
reversible. Server publication does not establish device ownership.

## 2. Stop All Writers and List

The adapter holds its store in memory and rewrites JSON non-atomically on storage
updates. A live edit can be overwritten; a live read may be incomplete or stale.
Stop **all** writers, including other profiles, containers and one-shot senders,
before maintenance. The CLI cannot reliably detect them. `--offline` is a
required acknowledgement for mutations, not a lock or automatic shutdown.
`list` warns that it is only a snapshot, even though it does not modify the file.

```bash
python -m omemo_trust --store /actual/path/xmpp_omemo.json list --jid alice@example.org
```

Output contains the JID, device ID, persisted trust grade and public fingerprint.
`MISSING` means no trust entry; the CLI can create a decision for this existing
identity, but never creates an identity. Persisted
`BLINDLY_TRUSTED` is not necessarily effective trust when BTBV is off. No private
identity, session or pre-key material is displayed. `list` without `--jid` lists
all recorded device identities.

Remote device IDs accept canonical decimal `1..4294967295`, including values
above the signed-32 maximum, and are listed in numeric order. Zero, negative
values, leading zeros and values above the unsigned-32 maximum are refused.
This is remote wire/store compatibility, not a change to own-device generation:
OMEMO:2 setup and the installed dependency generate positive signed-32 IDs.

For your own Docker Compose deployment, first check service, mounts, Python
environment and store-owner UID/GID. This repository ships no Compose stack.
An illustrative service named `hermes` with store-owner UID 10000 could use:

```bash
docker compose stop hermes
docker compose ps --all hermes
docker compose run --rm --no-deps -T --user 10000 --entrypoint python3 hermes -m omemo_trust --store /opt/data/xmpp_omemo.json list --jid alice@example.org
```

The module must be available in that maintenance container's working directory
or Python path, and all other writers must also be stopped.

Compare candidates with the published device list using an independent XMPP
client. An absent identity is not automatically a harmless ghost: investigate
stale publication, removal, replacement or compromise.

## 3. Independently Verify and Trust

Ask the contact for the new device's **own** fingerprint. Compare through an
independent authenticated channel, such as in person or a previously verified
device. An assertion from only the unverified new device is insufficient.
Confirm the intended JID and device ID and compare all 64 hexadecimal characters.
The CLI ignores ASCII presentation spaces and letter case, but no other content.

Keep every writer stopped and run as the store owner:

```bash
python -m omemo_trust --store /actual/path/xmpp_omemo.json trust --offline --jid alice@example.org --device-id 1001 --fingerprint 'INDEPENDENTLY VERIFIED 64 HEX CHARACTERS'
```

Replace the fingerprint placeholder with the independently verified value, not
simply a value copied from `list`. The CLI requires an existing recorded identity
with or without a trust entry, converts that public identity, checks the supplied
fingerprint, and writes only `TRUSTED`. A mismatch or invalid store is an error
with a nonzero exit status and no store update.

Successful mutations create a uniquely named, mode-0600 backup in the store
directory. **Backups contain the entire store, including secrets.** Protect the
directory and retain backups only as needed. The replacement preserves store
UID/GID and permission mode and is atomic on the same filesystem. Symlink store
files are refused. Atomic replacement does not make edits safe with a running
adapter, provide a complete power-loss durability guarantee, or preserve custom
ACLs/extended attributes. Use another maintenance method if those are required.

Trust is stored per JID and identity, not per device ID. If multiple recorded
devices share the same identity, changing that trust entry affects all of them.

## 4. Restart and Verify

Only after success, restart the writers. In the illustrative Compose deployment:

```bash
docker compose up -d hermes
docker compose logs --follow hermes
```

Test non-sensitive OMEMO messages in both directions from the verified device.
Confirm actual encryption/decryption, not just delivery or absence of warnings.
Check fresh trust, decryption and refused-encryption logs. Also test an unverified
device and ordinary plaintext input against the configured policy. Historical
warnings or warnings for other devices do not prove this update failed.

## Revocation and Lockout

To revoke, stop all writers again, then:

```bash
python -m omemo_trust --store /actual/path/xmpp_omemo.json distrust --offline --jid alice@example.org --device-id 1001
```

No fingerprint is required to set an existing identity's trust to `DISTRUSTED`.
Restart and verify subsequent behavior. Delivered or queued messages cannot be
recalled; this is not an instantaneous undo of previous encryption.

For lockout, use authenticated administration to repair verified trust.
`XMPP_REQUIRE_OMEMO_INBOUND=0` permits authorized plaintext input while OMEMO is
enabled, but does not repair trust/decryption or relax outbound encryption. It
exposes input to server injection and is not a trust-repair procedure.

## References and Limits

See [CLI implementation](../omemo_trust.py), [adapter](../adapter.py), and the
companion guide's store schema, conversion mathematics and dependency provenance.
The CLI is covered by temporary-store tests, including public conversion vectors
and mutation failures. It has not been tested against a live Hermes deployment,
real store or server bundle. Installed dependency versions may differ.
