# Hermes XMPP/Jabber plugin

Third-party XMPP/Jabber gateway platform plugin for Hermes Agent.

This packages the work from the upstream Hermes Agent XMPP PRs as an optional
user plugin so self-hosters can use XMPP now instead of waiting for the core PR
to land. It supports:

- 1:1 XMPP chats
- MUC group rooms
- mandatory STARTTLS to the XMPP server
- XEP-0085 typing indicators
- XEP-0363 HTTP file upload for media/files
- XEP-0004 data forms (e.g., clarify prompts)
- XEP-0050 ad-hoc commands
- XEP-0394 message markup (bold, code, lists)
- XEP-0461 threaded message replies
- XEP-0184 delivery receipts for requested, validated direct messages
- XEP-0333 displayed markers for accepted markable direct messages
- XEP-0444 message reactions (✅/❌ for processing completion)
- XEP-0447 stateless file sharing for voice messages
- OMEMO end-to-end encryption (enabled by default, needs optional dependencies)
- Secure inbound XEP-0454 decryption to private local files, with a 24-hour
  plugin cache lifetime; see [formats, security and retention limits](docs/inbound-media.md)
- cron and `send_message` delivery through a standalone sender hook
- Hermes platform plugin registration via `ctx.register_platform(...)`

Traffic is encrypted to your XMPP server with TLS. When OMEMO is enabled and
slixmpp-omemo is installed, 1:1 messages are also end-to-end encrypted so the
server cannot read message bodies. MUC text is sent without OMEMO; encrypted
media is supported only for 1:1 chats.

## Differences from Upstream

Compared with [fastfinge/hermes-xmpp-plugin](https://github.com/fastfinge/hermes-xmpp-plugin)
at `d01087a` (upstream HEAD checked on 2026-10-27):

- **Message security:** With OMEMO enabled, plaintext DM input is rejected by default,
  with an inbound-only debugging override. Outgoing text, edits and clarify prompts fail closed.
- **[Device trust](#device-trust):** Blind trust is off by default; incoming OMEMO DMs
  require trusted identities.
- **[Trust CLI](#trust-cli):** An argparse CLI lists devices and grants or revokes trust
  offline. Grants require a fingerprint independently verified by the operator;
  XEdDSA converts the stored key
  for comparison. Validated store updates use private backups and atomic replacement;
  listings are aligned and device IDs sorted numerically.
- **Clarifications and forms:** OMEMO prompts use encrypted numbered text. Form submissions
  require authorization; encrypted DMs ignore unauthenticated sibling forms.
- **Outgoing media:** Files, images, video and voice support AES-256-GCM sealing and encrypted XEP-0454
  links. Captions are separately encrypted; links stay intact. Sealing is global, unsupported
  targets including MUCs fail before upload, and sealed uploads pass only the file basename.
- **Incoming media:** At the upstream baseline, incoming file URLs remain `TEXT`, with no
  attachment download or populated media fields, whether the message uses OMEMO or not.
  This fork downloads and decrypts supported XEP-0454 attachments from authorized, trusted
  OMEMO DMs before handing them to Hermes as local `media_urls` and content-derived
  `media_types`. Images use `PHOTO`, video uses `VIDEO`, and other files use `DOCUMENT`.
  Audio uses `VOICE` so Hermes can automatically transcribe it; this deliberately includes
  music and does not infer whether an audio file is a voice note. Captions are preserved,
  while encryption URLs, keys and thumbnails are removed from dispatched text and raw
  stanzas are withheld. Public-HTTPS-only downloads have size, concurrency and cache limits.
  Files are private (`0600`, directory `0700`), with startup and periodic cleanup after a
  default 24-hour lifetime. That lifetime covers only the plugin cache, not Hermes-retained
  copies. Plaintext and MUC attachments are not fetched; OMEMO:2/SCE and other unsupported
  transfer formats are not delegated to the agent for decryption. See
  [Inbound Encrypted Attachments](docs/inbound-media.md) for supported formats and limits.
- **Message status:** XEP-0184 receipts acknowledge requested, validated direct messages
  before dispatch. XEP-0333 displayed markers acknowledge markable direct messages when
  processing starts, replacing the eyes reaction without a fallback. Completion reactions
  remain success/failure indicators. The bot does not request or track user read/delivery
  confirmations; receiving, starting processing and finishing processing are distinct states.
- **Display name:** XEP-0172 names support config, environment and a Hermes-home file fallback.
  Available and subscribe presence advertise the name; authorized subscriptions refresh presence.

## Credits

Most adapter code is derived from Eric Lars Lee's upstream PR #17469. Mibay's
PR #3105 is credited for earlier XMPP/OMEMO exploration. See `ATTRIBUTION.md`
for the full credit note. This repo exists because waiting is annoying, not
because the packager wants credit for other people's work. Tiny open-source goblin
energy, responsibly attributed.

## Install

From the Hermes profile you want to use:

```bash
cd ~/.hermes/plugins
git clone https://github.com/fastfinge/hermes-xmpp-plugin.git
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python -r ~/.hermes/plugins/hermes-xmpp-plugin/requirements.txt
hermes config set plugins.enabled '["hermes-xmpp-plugin"]'
```

If you run Hermes from a different checkout/venv, install requirements into that
Python environment instead.

Restart the gateway after installing or changing env vars:

```bash
hermes gateway restart
```

## Configure with env vars

Add these to the `.env` in the active profile's resolved Hermes home. This is
`~/.hermes/.env` for the default home, not necessarily for a named profile or
custom `HERMES_HOME`:

```env
XMPP_JID=hermes@example.org
XMPP_PASSWORD=your-password
XMPP_ALLOWED_USERS=sam@example.org
# Optional transport, display, room and home-channel settings:
# XMPP_HOST=example.org
# XMPP_PORT=5222
# XMPP_DIRECT_TLS=true   # force XEP-0368 direct TLS; auto-on when XMPP_PORT=5223
# XMPP_USE_IPV6=false    # disable IPv6 (default: auto-detect a working global v6 route)
# XMPP_CONNECT_TIMEOUT_SECS=240  # default 180s; raise further on a slow/high-latency link
# XMPP_DISPLAY_NAME=Hermes
# XMPP_MUC_ROOMS=room@conference.example.org/hermes
# XMPP_MUC_NICK=hermes
# XMPP_HOME_CHANNEL=sam@example.org

# OMEMO defaults (no need to set these explicitly):
# XMPP_OMEMO_ENABLED=true
# XMPP_OMEMO_BTBV=false
# XMPP_REQUIRE_OMEMO_INBOUND=1
# XMPP_OMEMO_MEDIA=true  # follows OMEMO enabled unless explicitly set
# XMPP_OMEMO_STORAGE_PATH=/path/to/active-profile/xmpp_omemo.json
# Storage defaults to xmpp_omemo.json in the resolved Hermes home.

# Inbound encrypted attachment cache defaults:
# XMPP_MEDIA_TTL_SECS=86400      # 24 hours; plugin cache only, not Hermes-retained copies
# XMPP_MEDIA_MAX_BYTES=26214400  # 25 MiB maximum encrypted attachment size
# XMPP_MEDIA_CACHE_BYTES=268435456  # 256 MiB cache quota, including download reservations
```

JID/password resolution uses Hermes' active-profile secret scope when available.
Credential preflight can also read that home's `.env` before dotenv loading;
under multiplexing, missing scoped credentials do not fall back to the launch
profile's process environment. This does not make every tuning option
profile-isolated: several options still read process environment directly.

See [Inbound Encrypted Attachments](docs/inbound-media.md) for download security,
automatic cleanup and the retention boundary of the inbound media cache.

`XMPP_ALLOWED_USERS` uses bare JIDs. MUC access is gated by room membership: if
the bot joins a room listed in `XMPP_MUC_ROOMS`, messages in that room are accepted.

Risky opt-outs, not part of the minimal setup:

- `XMPP_ALLOW_ALL_USERS=true` bypasses the DM allow-list; use only for controlled testing.
- `XMPP_OMEMO_ENABLED=false` deliberately enables plaintext DMs in both directions.
- `XMPP_REQUIRE_OMEMO_INBOUND=0` permits authorized plaintext DM input without relaxing outbound encryption.
- `XMPP_OMEMO_BTBV=true` enables blind trust for devices, not verified trust.
- `XMPP_OMEMO_MEDIA=false` disables upload sealing, including for MUC media; DM links still use OMEMO when enabled.

See [OMEMO Security Policy](#omemo-security-policy), [Encrypted Media](#encrypted-media)
and the [new-device trust runbook](docs/omemo-new-device-trust-runbook.md)
for the security implications and trust setup.

## Configure with config.yaml

You can also use config.yaml:

```yaml
plugins:
  enabled:
    - hermes-xmpp-plugin

xmpp:
  enabled: true
  jid: hermes@example.org
  password: ${XMPP_PASSWORD}
  allowed_users:
    - sam@example.org
  muc_rooms:
    - room@conference.example.org/hermes
  home_channel: sam@example.org
```

There is no blanket environment-first precedence: adapter config/extra values
generally take precedence over environment fallbacks, including OMEMO settings.
On single-profile hosts, YAML also fills some unset process variables without
overwriting existing ones; under multiplexing, those values stay in config/extra.

## OMEMO end-to-end encryption

The dependencies are optional to install, but OMEMO is enabled by default.
Default DM operation requires installed, usable OMEMO dependencies and trusted
recipient devices; missing dependencies or failed encryption do not cause a
plaintext fallback. Install the extras into the gateway's Python environment:

```bash
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python slixmpp-omemo omemo
```

OMEMO needs no explicit enable flag. To customize storage, use the active
profile's `.env` (replace the illustrative path with that profile's actual home):

```env
# XMPP_OMEMO_ENABLED=true  # already the default
# Optional: defaults to xmpp_omemo.json in the resolved Hermes home
XMPP_OMEMO_STORAGE_PATH=/path/to/active-profile/xmpp_omemo.json
```

Or in `config.yaml`:

```yaml
xmpp:
  omemo_enabled: true
  omemo_storage_path: /path/to/active-profile/xmpp_omemo.json
```

On first connect, the adapter generates an OMEMO device key and publishes it to
the server. This may take a few seconds — the adapter waits for initialization
before sending encrypted messages. If the recipient hasn't published usable,
trusted device keys yet, direct-message encryption fails closed rather than
falling back to plaintext.

MUC text is plaintext at the OMEMO layer (still transported over TLS), even when
OMEMO is enabled. Encrypted media is unsupported in MUCs and fails before upload
with the default media setting. See [Encrypted Media](#encrypted-media) for the
explicit plain-upload opt-out and [OMEMO Security Policy](#omemo-security-policy)
for encryption rules. Before your first successful DM, follow
[First Trusted Device](#first-trusted-device); device trust is required by default.

## First Trusted Device

Trust applies to a contact's recorded OMEMO device identity, not their whole
account. Repeat verification for other devices. The commands below assume the
default Hermes home and gateway lifecycle; use the active profile's actual store,
Python environment and service/container controls if different. Run the CLI from
this plugin's checkout, as the store owner, with the OMEMO dependencies installed.

1. Add your client's bare JID to the active profile's `.env`, for example
   `XMPP_ALLOWED_USERS=alice@example.org`. Keep OMEMO enabled and BTBV disabled.
2. Start or restart the gateway with `hermes gateway restart`. Enable OMEMO in
   your client's chat with the bot and send a non-sensitive test message. The
   adapter needs an authorized sender and usable published device keys to discover
   the identity. The message is discarded until the device is trusted; no reply
   is expected yet.
3. Stop the gateway with `hermes gateway stop` and stop **all other writers** of
   this store, including other processes, containers and standalone senders. List
   the discovered identities:

```bash
python -m omemo_trust --store ~/.hermes/xmpp_omemo.json list --jid alice@example.org
```

4. Identify the sending device and compare its listed fingerprint with the
   device's own fingerprint shown in your client. Verify all 64 hexadecimal
   characters independently: inspect your own client directly, or use an
   authenticated channel for someone else's device. Do not grant trust just
   because a fingerprint appears in the list or arrives from the unverified device.
5. Keep every writer stopped. Replace the example device ID and fingerprint
   placeholder with the independently verified values, then grant trust:

```bash
python -m omemo_trust --store ~/.hermes/xmpp_omemo.json trust --offline --jid alice@example.org --device-id 1001 --fingerprint 'INDEPENDENTLY VERIFIED 64 HEX CHARACTERS'
```

6. Only after the command succeeds, start the gateway with `hermes gateway start`.
   Resend the test message and verify encrypted messages in both directions.
   The initial discarded message is not replayed automatically. Verify the bot's
   fingerprint in your client as well; do not bypass the client's trust checks.

If no identity is listed, do not enable blind trust or fabricate a store entry.
Check the allow-list, actual store/profile path, OMEMO initialization, client
device publication and bundle availability. A failed first message does not
guarantee identity discovery. `--offline` only acknowledges that writers are
stopped; it does not stop them or acquire a lock.

See [Trust CLI](#trust-cli) for store selection, backups and revocation, and the
[new-device trust runbook](docs/omemo-new-device-trust-runbook.md) for detailed
discovery troubleshooting and container maintenance.

## Multiple Hermes profiles

XMPP is nice for profile isolation because you can create one JID per profile:

- `sam-hermes@example.org` for your profile
- `mom-hermes@example.org` for Mom's profile
- `dad-hermes@example.org` for Dad's profile

Each Hermes profile gets its own `.env`, memory, sessions, and gateway process.

## Server notes

Prosody needs modules for MUC, HTTP file upload, and the new XEPs. On Debian/Ubuntu:

```bash
sudo apt install prosody
sudo prosodyctl adduser hermes@example.org
```

Enable/configure in Prosody:
- `muc` — group rooms
- `http_file_share` — file upload (XEP-0363)
- `mod_groups` — optional, for ad-hoc command roster

For ejabberd, enable MUC plus `mod_http_upload`. The new features (reactions,
replies, markup) use standard XMPP stanzas and should work on any modern server
supporting XEP-0444, XEP-0461, and XEP-0394.

## Troubleshooting

- `xmpp_auth_failed`: wrong JID/password, or server auth policy issue.
- `xmpp_connect_timeout`: the gateway will report the platform as connected
  right away (connecting doesn't block gateway startup), but a background
  watchdog gives up and retries if the session hasn't actually established
  within `XMPP_CONNECT_TIMEOUT_SECS` (default 180s). A common cause on home
  networks: DNS returns both an A and AAAA record for the server, the IPv6
  route is silently blackholed, and the OS burns through its full TCP retry
  budget (~130s on Linux defaults) before falling back to IPv4 — which then
  connects instantly. Check `python3 -c "import socket;
  print(socket.getaddrinfo('your.server', 5222))"` for a AAAA record, test
  IPv6 reachability separately (`ping6`/`curl -6`), and either fix IPv6
  routing or disable IPv6 for this host if it's not actually usable. If
  raising `XMPP_CONNECT_TIMEOUT_SECS` further fixes it, that confirms this
  cause. Otherwise it's a DNS/firewall/SRV/reachability issue — try
  `XMPP_HOST`/`XMPP_PORT` or check the server is reachable at all.
- `xmpp_connection_lost`: an established session dropped unexpectedly (server
  restart, network blip); the gateway's reconnect watcher should retry.
- `xmpp_lock`: another gateway process is already logged into this JID; stop
  it first, or use a separate bot account per gateway.
- HTTP upload failure: enable XEP-0363 on the server and check max file size.
- DM rejected: add your bare JID to `XMPP_ALLOWED_USERS`.
- MUC silent: add room to `XMPP_MUC_ROOMS` and invite the bot.

## Features in depth

### Delivery receipts (XEP-0184)

The adapter acknowledges an authorized direct message that requests a delivery
receipt and has a non-empty message ID and usable body. For OMEMO, successful
decryption and device trust checks are required first. The receipt uses the
original wire request and ID and is routed to the sender's full JID, including
the resource when present.

Delivered means received and validated by the adapter, not queued, processed,
read by a person, or successfully answered. The receipt is sent before dispatch,
even if the handoff later fails or processing never starts. The separate
`displayed` marker below indicates processing start.

Automatic Slixmpp replies and outbound receipt requests are disabled. Group
messages, empty bodies, missing IDs, and receipt acknowledgements are not
acknowledged. Incoming user receipts are not tracked. There is no new setting;
receipts are independent of `XMPP_REACTIONS` and are unencrypted stanza metadata,
including for OMEMO messages.

### Displayed markers (XEP-0333)

When Hermes starts processing an authorized direct message with a message ID and
an original `<markable/>` extension, the adapter sends a `displayed` marker.
Receipt alone does not trigger it: rejected messages and failed handoffs before
processing starts are not marked. OMEMO messages use the original stanza ID and
markable flag after successful decryption and trust checks. Queued messages are
marked only when the processing-start hook runs.

Markers replace the previous eyes reaction, with no reaction fallback. They are
independent of `XMPP_REACTIONS`. Group messages are not marked. Outgoing messages
do not request markers and incoming user read markers are not tracked.
Like delivery receipts and reactions, these markers are unencrypted
stanza metadata, including for OMEMO messages.

### Message reactions (XEP-0444)

When processing finishes, ✅ or ❌ is sent depending on success or error.
Reactions are visible in clients that support XEP-0444 (Conversations, Dino,
Gajim, etc.).

Reactions can also be sent by Hermes tools; the adapter maps the reaction to the
original message using slixmpp's `xep_0444`.

### Threaded replies (XEP-0461)

When you reply to a bot message, the adapter tracks the thread using XEP-0461
message references. Replies from Hermes are sent back into the same thread so
context is preserved.

### Message markup (XEP-0394)

Markdown-like syntax in Hermes responses is converted to XEP-0394 message markup:
- `**bold**` → `<span style="font-weight: bold">bold</span>
- `` `code` `` → `<code>code</code>
- `` ```block``` `` → `<blockcode>block</blockcode>
  
Clients that support XEP-0394 render this natively. Others get the raw text.

### Data forms (XEP-0004) for clarify

OMEMO direct-chat clarifications use encrypted numbered text, never sibling
data forms. In plaintext mode or configured MUC rooms, the adapter can send an
XEP-0004 data form when the plugin is available. The form includes:
- A hidden `clarify_id` field
- A list-single choice field with the available options
- An "Other (type your own answer)" option for free-form responses

The message body also includes a numbered text fallback so that clients which
do not render `jabber:x:data` forms in `<message>` stanzas (Conversations,
ConverseJS, older Gajim) still display actionable choices. Users on those
clients can reply with the number or option text as normal.

When a client does render the form and the user submits it, the adapter reads
the form response, extracts the `clarify_id` and selected answer, and resolves
the clarification back to Hermes only when the pending request belongs to the
same gateway session. Authorization alone does not grant access to another
chat's request. Room participant isolation follows Hermes' session policy and
the same source identity used for ordinary message dispatch (anonymous rooms
fall back to room identity).

Form responses require Hermes' `tools.clarify_gateway.get_pending` API and the
base adapter's `_source_session_key` helper. These APIs were inspected in upstream
Hermes source; older hosts lacking them refuse submissions rather than resolve
global IDs without an ownership check. Use numbered text replies on such hosts.

**Disabling data forms:** If you prefer to always use plain text clarify
(never send XEP-0004 forms), set the environment variable
`XMPP_DISABLE_CLARIFY_FORMS=true` or add `disable_clarify_forms: true` to your
XMPP platform config in `config.yaml`. This forces the numbered text fallback
path even when the `xep_0004` plugin is registered.

### Voice messages (XEP-0447)

With default OMEMO media sealing, voice files are encrypted before XEP-0363
upload and delivered as an intact XEP-0454 `aesgcm://` link in an encrypted DM
body, not a plaintext SFS reference. MUC voice uploads fail before upload under
this default. With sealing explicitly disabled, the plain-upload path can use
XEP-0447 Stateless File Sharing references for client metadata previews.

Voice calls (Jingle) are not yet supported because slixmpp does not include a
Jingle RTP implementation.

### Ad-hoc commands (XEP-0050)

The adapter registers ad-hoc commands on the bot's JID. Users can discover them
with their client's command list (e.g., `/cmd` in Conversations). Currently a
basic command list is exposed; future releases may add Hermes-specific commands.

## Development

The test suite runs standalone — no Hermes checkout required. It uses mocks for the
Hermes gateway and slixmpp internals.

```bash
python -m pytest -q
```

For testing against a real Hermes checkout, set `PYTHONPATH`:

```bash
PYTHONPATH=/path/to/hermes-agent python -m pytest -q
```

## OMEMO Security Policy

OMEMO is enabled by default. Direct-message bodies, corrections and clarify
questions fail closed if encryption is unavailable or fails. Plaintext direct
messages, including bodyless form submissions, are ignored by default while
OMEMO is configured. Set `XMPP_OMEMO_ENABLED=false` only to intentionally use
plaintext for both directions.
OMEMO clarifications use numbered encrypted text, not legacy data forms.
Form submissions in plaintext mode are checked against the allow-list and the
owning gateway session. Only known/configured MUC rooms receive groupchat
exemptions, even when `XMPP_ALLOW_ALL_USERS=true`.

`XMPP_REQUIRE_OMEMO_INBOUND=0` (also `false` or `no`, case-insensitive) allows
authorized plaintext direct input while OMEMO remains configured. This is an
inbound-only debugging override: plaintext bodies and bodyless form submissions
are unauthenticated and can be injected by the server. The default is strict;
empty or unrecognized values do not disable it. The override does not relax
outbound encryption, device trust checks, decryption failures or authorization.
Sibling forms on encrypted direct messages remain ignored, because legacy
OMEMO does not authenticate them. When OMEMO is disabled, plaintext input
continues to work regardless of this setting. MUC behavior is unchanged.

MUC text behavior is unchanged. Legacy OMEMO protects bodies, not all stanza
metadata: corrections, reactions, typing, retractions and sibling extensions
are not covered by a blanket authenticity guarantee. Legacy data forms are
never acted on beside an encrypted direct-message body, even with the inbound
plaintext override enabled.

## Device Trust

New devices are not blindly trusted by default. `XMPP_OMEMO_BTBV=true` opts
into blind trust. Explicitly `TRUSTED` decisions remain effective. The
dependency treats `BLINDLY_TRUSTED` as undecided when BTBV is off; outbound
manual-trust handling can mark such devices `DISTRUSTED`. With all store
writers stopped, use the [Trust CLI](#trust-cli) to set the existing identity's
trust to `TRUSTED` after verifying the fingerprint out of band, then restart. `BLINDLY_TRUSTED`
is accepted only with BTBV enabled, and is not verified trust. Incoming direct
messages require effective device trust, not just successful decryption.

BTBV is an outbound trust-decision policy, not automatic inbound approval:
turning it on does not promote an incoming `UNDECIDED` device. Successfully
decrypted untrusted DMs are discarded; `UNDECIDED` is persisted for discovery.
The dependency records real bundle identities before decryption. Discovery
requires authorization, initialized OMEMO, a published/downloadable bundle and
usable key material. A decryption failure may leave a recorded identity without
a trust entry, or no identity at all. No identity is fabricated.

## Trust CLI

For offline trust maintenance, run the argparse CLI from this repository using
the adapter's Python environment with the optional OMEMO dependencies installed:

```bash
python -m omemo_trust --store /actual/path/xmpp_omemo.json list --jid alice@example.org
python -m omemo_trust --store /actual/path/xmpp_omemo.json trust --offline --jid alice@example.org --device-id 1001 --fingerprint 'INDEPENDENTLY VERIFIED 64 HEX CHARACTERS'
python -m omemo_trust --store /actual/path/xmpp_omemo.json distrust --offline --jid alice@example.org --device-id 1001
```

Stop **all writers** first: the adapter caches the store and can overwrite edits.
`--offline` acknowledges this; it does not detect writers or stop them. `list`
is only a snapshot and warns about live reads. Trust requires an independently
verified fingerprint matching an existing recorded identity. A missing trust
entry can be created for that identity by either `trust` or `distrust`; missing
identities are refused. Remote device IDs accept canonical decimal integers
`1..4294967295` and sort numerically. This unsigned wire/store acceptance does
not change the dependency's signed-32 local ID generation; zero is excluded.
Mutations make a private backup containing secrets and atomically preserve store mode and
ownership; custom ACLs/extended attributes are not preserved. Without `--store`,
the CLI uses `XMPP_OMEMO_STORAGE_PATH` or `xmpp_omemo.json` under the resolved
Hermes home. It does not load adapter configuration or `.env`.

For operator procedures, see the [fingerprint and trust guide](docs/omemo-fingerprints-and-trust-guide.md)
and [new-device trust runbook](docs/omemo-new-device-trust-runbook.md).

## Encrypted Media

`omemo.media` (nested YAML), `omemo_media` (flat YAML/extra), or
`XMPP_OMEMO_MEDIA` controls XEP-0454 sealed uploads. It defaults to the OMEMO
enabled setting, so deliberately plaintext installations retain plain uploads.
This is a global option with no per-destination override. Setting it true
requires usable 1:1 OMEMO; MUC media, disabled OMEMO and missing plugins fail
before upload. Setting it false permits plain MUC media but disables upload
sealing globally, including for DMs; DM links still use OMEMO when enabled.

Files, images, video and voice are AES-256-GCM sealed before HTTP upload.
Only ciphertext and its authentication tag reach the upload service. The
`aesgcm://` URI carries hex-encoded IV followed by key and is sent intact in
one encrypted body. Captions are separate encrypted messages; failures stop
delivery. Encryption failures never downgrade to plaintext. When sealing is
disabled but OMEMO remains enabled, direct-chat links still use OMEMO.

Sealing buffers the file in memory. Upload services still see file names,
sizes and request metadata. A failure after upload may leave orphan ciphertext;
delivery is not transactional and a caption can arrive before a failed upload.

## Display Name

Set `display_name` in XMPP YAML/extra or `XMPP_DISPLAY_NAME` to advertise a
XEP-0172 nickname in available and subscribe presence. Extra takes precedence
over environment. If neither supplies a nonblank name, the adapter reads
the UTF-8 file `xmpp_display_name` in Hermes home (resolved by `hermes_home`).
Missing or unreadable files are ignored. Existing nickname elements are kept;
unavailable, probe and subscription-approval stanzas are not stamped.

Presence is refreshed after authorized subscription requests or approvals.
Clients may require mutual presence subscriptions to display the nickname;
this does not change the account JID, MUC nickname or vCard.
