# Inbound Encrypted Attachments

The plugin decrypts supported attachments before Hermes sees them. Events contain
absolute local `media_urls`, parallel content-derived `media_types`, and empty
plugin metadata. Encryption URLs and thumbnails are removed from event and reply
text. Raw stanzas are not forwarded. Failed downloads produce generic notices,
not URLs, keys, or exception details.
Redaction consumes complete non-whitespace `aesgcm:` tokens, case-insensitively,
including quotes and angle brackets inside malformed or unsupported links.

## Supported Input

- XEP-0454: one `aesgcm://` body line, optionally followed by an image data URI.
  The fragment is exactly 88 hexadecimal characters: 12-byte IV, then 32-byte
  AES key. The encrypted file ends with the 16-byte GCM authentication tag.
- Captions with OOB (XEP-0066) or SFS (XEP-0447) URL sources are supported when
  the attachment URI is also a complete line in the authenticated body.
  Legacy OMEMO XML siblings are not authenticated, so XML alone cannot authorize
  a fetch. Prose links are never downloaded.
- The parser accepts OOB/SFS sources from successfully SCE-decrypted stanzas.
  This is a dependency capability seam, NOT working OMEMO:2 support with the
  currently installed slixmpp-omemo: its `decrypt_message` explicitly raises
  `NotImplementedError` for SCE unpacking. Such input is discarded by the existing
  OMEMO receive gate. Legacy OMEMO continues through that gate unchanged.
- Only authorized, effectively trusted, decrypted direct messages fetch media.
  Plaintext and MUC input never authorize network retrieval. Disabling the
  plaintext-message gate does not disable this policy. Explicit BTBV remains
  an operator trust decision.

16-byte-IV variants are not accepted: XEP-0454 specifies 12 bytes and no client
source confirming a particular 16-byte format was available during implementation.
Other encodings, XEP-0448 encrypted SFS sources, Jingle/IBB and plaintext upload
URLs are not implemented. Unsupported `aesgcm:` tokens are still sanitized.
This is not a promise to decrypt every XMPP encryption/file-transfer protocol.

## Network And Storage

HTTPS only, verified TLS, port 443 only, no userinfo, no environment proxies,
no redirects, no HTTP content decompression. Every DNS answer must be public;
mixed public/private answers are rejected. The aiohttp resolver returns validated
numeric addresses directly to its connector, preventing a separate unchecked DNS
lookup at connection time. Literal addresses receive the same checks because
aiohttp bypasses its resolver for those. URLs are first canonicalized with yarl;
the canonical `raw_host` is checked and the same URL object is used for fetching,
including Unicode hostnames that normalize to IP literals. Loopback, private, reserved, multicast,
mapped IPv6 and IPv6 transition addresses are refused. Egress firewall rules
remain useful defense in depth: public services can themselves proxy requests.

Defaults: 25 MiB encrypted bytes per attachment, 256 MiB cache quota, three active
downloads, twelve admitted fetches including waiters, and a 60-second deadline
per fetch including queueing and DNS. At most four XML attachments per event.
There are no automatic retries; later deliveries can retry safely with new UUID
names. Quota reserves twice the size cap per download conservatively, so a nearly
full cache may reject a file that would fit. No early eviction for quota pressure.
The cache also caps entry count at 1024, preventing tiny-file inode exhaustion.

The directory is `$HERMES_HOME/cache/xmpp-inbound` (0700). Published files and
unfinished `.part` files are created exclusively with 0600. Directory traversal
uses no-follow descriptors; cache operations are descriptor-relative. Each sweep
and quota scan opens a fresh directory descriptor so its scan state is independent
of earlier scans and the held cache descriptor's offset. Streaming
GCM writes unverified plaintext only into private temporary files. Atomic,
exclusive publication happens only after tag verification. Cancellation, timeout
and authentication failure unlink temporary plaintext. No full-file buffering.

MIME recognition uses byte signatures, never filenames, URL suffixes or HTTP
headers: PNG, JPEG, GIF, WebP, AVIF, PDF, ZIP, FLAC, ID3 MP3, WAV, Ogg
Opus/Vorbis, common MP4/M4A brands, WebM and AVI. Unknown content is a document
with `application/octet-stream` and `.bin`. ZIP is not guessed as Office content.
Signatures classify content but do not establish safety or structural validity.
For recognized MP4/M4A brands, the verified plaintext descriptor is inspected
before publication: only `moov/trak/mdia/hdlr` boxes are traversed, including a
`moov` after `mdat`. All tracks must identify as `soun` to produce `audio/mp4`
and `.m4a`; video, mixed, unknown or malformed layouts remain `video/mp4`.
The scan permits at most 1024 boxes and four hierarchy levels, reads at most
40 KiB of box headers/handler fields, and seeks past payloads without buffering
them. Normal, extended and zero-to-container-end box sizes are bounded by their
container and file. Filenames and SFS MIME metadata never override this analysis.

## Retention Boundary

Startup removes unfinished and expired entries. A plugin-owned task sweeps
independently of downloads every five minutes (or TTL if shorter). Default TTL
is 24 hours, based on file mtime. Disconnect, including unexpected connection
loss, cancels and awaits downloads and the sweep task. While stopped there is no
sweep; startup catches up. Successful automatic slixmpp reconnects restart the
cache through session readiness, including `session_start`, without duplicating
the sweep task. Unlinking is not secure erasure and cannot remove
backups or filesystem snapshots.

Hermes owns its own retention. `gateway/run_inbound_media.py` can move files into
the active routed profile cache. Native admission/persistence can also capture
retained media. The plugin does NOT track or delete moved files, retained blobs,
extracted text, transcripts or agent copies. Hermes' rehoming code does not ensure
destination directories are 0700. Configure Hermes profile/cache/state retention
separately. A claim that all Hermes media disappears after 24 hours would be false.

## Configuration

Optional scoped environment variables, exposed in `plugin.yaml`:

- `XMPP_MEDIA_TTL_SECS`: default `86400`; extra `media_ttl_secs`.
- `XMPP_MEDIA_MAX_BYTES`: default `26214400`; extra `media_max_bytes`.
- `XMPP_MEDIA_CACHE_BYTES`: default `268435456`; extra `media_cache_bytes`.

Values must be positive and finite; invalid values fail adapter construction.
No plaintext/MUC fetch override is provided.

## Source Evidence

- [XEP-0454 sections 3-5 and 7](https://xmpp.org/extensions/xep-0454.html):
  IV/key ordering and size, trailing tag, strict layout, thumbnail and secrecy.
- Installed `slixmpp_omemo/xep_0384.py`, `decrypt_message`: legacy body replacement
  and explicitly unimplemented SCE unpacking.
- Hermes `gateway/platforms/event.py`: local path and parallel MIME contract.
- Hermes `gateway/session_envelope.py`: native media validation and capture.
- Hermes `gateway/run_inbound.py`: rehome before consumption.
- Hermes `gateway/run_inbound_media.py`: profile-relative cache move/rewrite.
- Hermes `gateway/session_ingress_media.py`: retained native attachment capture.

Tests use real AES-GCM and mocked streaming HTTP responses. They exercise the
real aiohttp resolver/connector resolution path, but are not live-server TLS or
Conversations/Gajim interoperability tests. The review bundle was not merged.
