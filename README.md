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
- XEP-0444 message reactions (e.g., 👀/✅/❌ for processing status)
- XEP-0447 stateless file sharing for voice messages
- OMEMO end-to-end encryption (optional, needs slixmpp-omemo)
- cron and `send_message` delivery through a standalone sender hook
- Hermes platform plugin registration via `ctx.register_platform(...)`

Traffic is encrypted to your XMPP server with TLS. When OMEMO is enabled and
slixmpp-omemo is installed, 1:1 messages are also end-to-end encrypted so the
server cannot read content. MUC OMEMO support depends on client/device
availability.

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

Add these to `~/.hermes/.env` for the active profile:

```env
XMPP_JID=hermes@example.org
XMPP_PASSWORD=your-password
XMPP_ALLOWED_USERS=sam@example.org
# Optional:
XMPP_HOST=example.org
XMPP_PORT=5222
# XMPP_DIRECT_TLS=true   # force XEP-0368 direct TLS; auto-on when XMPP_PORT=5223
# XMPP_USE_IPV6=false    # disable IPv6 (default: auto-detect a working global v6 route)
# XMPP_CONNECT_TIMEOUT_SECS=240  # default 180s; raise further on a slow/high-latency link
XMPP_MUC_ROOMS=room@conference.example.org/hermes
XMPP_MUC_NICK=hermes
XMPP_HOME_CHANNEL=sam@example.org
```

`XMPP_ALLOWED_USERS` uses bare JIDs. MUC access is gated by room membership: if
the bot joins a room listed in `XMPP_MUC_ROOMS`, messages in that room are accepted.
For quick local testing only, set `XMPP_ALLOW_ALL_USERS=true`.

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

Env vars win when both are set.

## OMEMO end-to-end encryption (optional)

Install the extra dependencies:

```bash
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python slixmpp-omemo omemo
```

Then set in `~/.hermes/.env`:

```env
XMPP_OMEMO_ENABLED=true
# Optional — defaults to ~/.hermes/xmpp_omemo.json
XMPP_OMEMO_STORAGE_PATH=/home/fastfinge/.hermes/xmpp_omemo.json
```

Or in `config.yaml`:

```yaml
xmpp:
  omemo_enabled: true
  omemo_storage_path: /home/fastfinge/.hermes/xmpp_omemo.json
```

On first connect, the adapter generates an OMEMO device key and publishes it to
the server. This may take a few seconds — the adapter waits for initialization
before sending encrypted messages. If the recipient hasn't published usable,
trusted device keys yet, direct-message encryption fails closed rather than
falling back to plaintext.

MUC OMEMO is supported when all participants have compatible devices, but group
encryption reliability varies by client. 1:1 encryption is the primary use case.

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

### Message reactions (XEP-0444)

When Hermes starts processing a request, the adapter sends a 👀 reaction. When it
finishes, ✅ or ❌ is sent depending on success or error. Reactions are visible in
clients that support XEP-0444 (Conversations, Dino, Gajim, etc.).

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

When Hermes needs clarification, the adapter sends an XEP-0004 data form instead
of a plain text list. The form includes:
- A hidden `clarify_id` field
- A list-single choice field with the available options
- An "Other (type your own answer)" option for free-form responses

The message body also includes a numbered text fallback so that clients which
do not render `jabber:x:data` forms in `<message>` stanzas (Conversations,
ConverseJS, older Gajim) still display actionable choices. Users on those
clients can reply with the number or option text as normal.

When a client does render the form and the user submits it, the adapter reads
the form response, extracts the `clarify_id` and selected answer, and resolves
the clarification back to Hermes automatically.

**Disabling data forms:** If you prefer to always use plain text clarify
(never send XEP-0004 forms), set the environment variable
`XMPP_DISABLE_CLARIFY_FORMS=true` or add `disable_clarify_forms: true` to your
XMPP platform config in `config.yaml`. This forces the numbered text fallback
path even when the `xep_0004` plugin is registered.

### Voice messages (XEP-0447)

Voice messages from Hermes are sent as XEP-0447 Stateless File Sharing (SFS)
messages. The file is uploaded via XEP-0363 HTTP upload first, then a lightweight
SFS reference is sent. This allows clients to preview metadata before downloading.

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
Form submissions in plaintext mode are checked against the allow-list first.

`XMPP_REQUIRE_OMEMO_INBOUND=0` (also `false` or `no`, case-insensitive) allows
authorized plaintext direct input while OMEMO remains configured. This is an
inbound-only debugging override: plaintext bodies and bodyless form submissions
are unauthenticated and can be injected by the server. The default is strict;
empty or unrecognized values do not disable it. The override does not relax
outbound encryption, device trust checks, decryption failures or authorization.
Sibling forms on encrypted direct messages remain ignored, because legacy
OMEMO does not authenticate them. When OMEMO is disabled, plaintext input
continues to work regardless of this setting. MUC behavior is unchanged.

New devices are not blindly trusted by default. `XMPP_OMEMO_BTBV=true` opts
into blind trust. Explicitly `TRUSTED` decisions remain effective. The
dependency treats `BLINDLY_TRUSTED` as undecided when BTBV is off; outbound
manual-trust handling can mark such devices `DISTRUSTED`. With all store
writers stopped, use the CLI below to set the existing identity's trust to
`TRUSTED` after verifying the fingerprint out of band, then restart. `BLINDLY_TRUSTED`
is accepted only with BTBV enabled, and is not verified trust. Incoming direct
messages require effective device trust, not just successful decryption.

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
verified fingerprint matching an existing identity and trust entry. Mutations
make a private backup containing secrets and atomically preserve store mode and
ownership; custom ACLs/extended attributes are not preserved. Without `--store`,
the CLI uses `XMPP_OMEMO_STORAGE_PATH` or `xmpp_omemo.json` under the resolved
Hermes home. It does not load adapter configuration or `.env`.

For operator procedures, see the [fingerprint and trust guide](docs/omemo-fingerprints-and-trust-guide.md)
and [new-device trust runbook](docs/omemo-new-device-trust-runbook.md).

MUC text behavior is unchanged. Legacy OMEMO protects bodies, not all stanza
metadata: corrections, reactions, typing, retractions and sibling extensions
are not covered by a blanket authenticity guarantee. Legacy data forms are
never acted on beside an encrypted direct-message body, even with the inbound
plaintext override enabled.

## Encrypted Media

`omemo.media` (nested YAML), `omemo_media` (flat YAML/extra), or
`XMPP_OMEMO_MEDIA` controls XEP-0454 sealed uploads. It defaults to the OMEMO
enabled setting, so deliberately plaintext installations retain plain uploads.
Explicitly enabling media requires usable 1:1 OMEMO; MUCs, disabled OMEMO and
missing plugins fail before upload. Set media false to retain plain MUC media.

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
