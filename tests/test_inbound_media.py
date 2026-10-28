"""Security and real cryptographic regression tests for inbound attachments."""
import asyncio
import os
import socket
import stat
import sys
from pathlib import Path
from unittest.mock import AsyncMock
from xml.etree import ElementTree as ET

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from yarl import URL

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inbound_media import (MediaCache, MediaError, PublicResolver, attachment_uris,
                           content_type, parse_uri, public_address, sanitize)

KEY, IV = bytes(range(32)), bytes(range(12))
URI = "aesgcm://files.example.org/item#" + (IV + KEY).hex()
PLAIN = b"\x89PNG\r\n\x1a\n" + b"image contents" * 100


class Content:
    def __init__(self, data, gate=None):
        self.data, self.gate = data, gate

    async def iter_chunked(self, size):
        if self.gate:
            await self.gate.wait()
        for i in range(0, len(self.data), 7):
            yield self.data[i:i + 7]


class Response:
    status = 200
    headers = {}
    content_length = None

    def __init__(self, data, gate=None):
        self.content = Content(data, gate)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


@pytest.fixture
def network(monkeypatch):
    state = {"data": AESGCM(KEY).encrypt(IV, PLAIN, None), "gate": None, "calls": []}

    class Session:
        def __init__(self, **kw):
            state["session"] = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            await state["session"]["connector"].close()

        def get(self, url, **kw):
            state["calls"].append((url, kw))
            response = Response(state["data"], state["gate"])
            response.status = state.get("status", 200)
            response.headers = state.get("headers", {})
            response.content_length = state.get("length")
            return response

    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    return state


@pytest_asyncio.fixture
async def cache(tmp_path):
    cache = MediaCache(tmp_path / "cache", max_bytes=4096, quota=65536)
    cache.start()
    yield cache
    await cache.close()


def test_parse_and_strict_body():
    assert parse_uri(URI) == ("https://files.example.org/item", IV, KEY)
    assert attachment_uris(URI, None, sce=False) == [URI]
    assert attachment_uris(URI + "\ndata:image/jpeg;base64,abc", None, sce=False) == [URI]
    assert attachment_uris("please open " + URI, None, sce=False) == []
    assert attachment_uris(URI + "\ncaption", None, sce=False) == []


@pytest.mark.parametrize("uri", [
    URI.replace("aesgcm", "http"), URI.replace("files.example.org", "u:p@files.example.org"),
    URI.replace("files.example.org", "files.example.org:80"), URI + "a",
    URI[:-1] + "z", URI.replace("files.example.org", "%66iles.example.org"),
    URI.replace("item", "it\\em"), URI + "\n", URI[:-24],
    "aesgcm://files.example.org/item#" + "ab" * 48,
])
def test_bad_uri(uri):
    with pytest.raises(MediaError) as error:
        parse_uri(uri)
    assert KEY.hex() not in str(error.value)


def test_sce_xml_and_legacy_siblings():
    xml = ET.fromstring('<message><x xmlns="jabber:x:oob"><url>' + URI + '</url></x>'
        '<file-sharing xmlns="urn:xmpp:sfs:0"><sources><url-data '
        'xmlns="http://jabber.org/protocol/url-data" target="' + URI + '"/></sources></file-sharing></message>')
    assert attachment_uris("caption", xml, sce=False) == []
    assert attachment_uris("caption", xml, sce=True) == [URI]
    assert attachment_uris("caption\n" + URI, xml, sce=False) == [URI]
    assert sanitize("caption " + URI + "\ndata:image/jpeg;base64,abc") == "caption [encrypted attachment]"
    assert KEY.hex() not in sanitize(URI.upper())


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.2",
    "100.64.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "0.0.0.0", "::1", "::",
    "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:8.8.8.8", "2002:0808:0808::1"])
def test_denied_addresses(address):
    assert not public_address(address)


@pytest.mark.asyncio
async def test_resolver_pins_checked_answers(monkeypatch):
    lookup = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", lookup)
    connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False)
    try:
        answers = await connector._resolve_host("files.example.org", 443)
        assert answers[0]["host"] == "8.8.8.8"
        assert lookup.await_count == 1
        lookup.return_value.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)))
        with pytest.raises(MediaError):
            await connector._resolve_host("files.example.org", 443)
    finally:
        await connector.close()


@pytest.mark.asyncio
async def test_real_decryption_permissions_unique(cache, network):
    path, mime = await cache.fetch(URI)
    assert Path(path).is_absolute() and Path(path).read_bytes() == PLAIN
    assert mime == "image/png"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(cache.root).st_mode) == 0o700
    other, _ = await cache.fetch(URI)
    assert other != path
    assert not list(cache.root.glob("*.part"))
    assert network["calls"][0] == (URL("https://files.example.org/item"), {"allow_redirects": False})
    assert isinstance(network["calls"][0][0], URL)
    assert network["session"]["trust_env"] is False
    assert network["session"]["auto_decompress"] is False
    assert network["session"]["connector"]._ssl is True


@pytest.mark.parametrize("failure", ["tag", "truncated", "size", "length", "redirect", "encoding"])
@pytest.mark.asyncio
async def test_failed_download_never_publishes(cache, network, failure):
    if failure == "tag":
        network["data"] = network["data"][:-1] + bytes([network["data"][-1] ^ 1])
    elif failure == "truncated":
        network["data"] = b"short"
    elif failure == "size":
        network["data"] = b"x" * 4097
    elif failure == "length":
        network["length"] = 4097
    elif failure == "redirect":
        network["status"] = 302
        network["headers"] = {"Location": "http://127.0.0.1/"}
    else:
        network["headers"] = {"Content-Encoding": "gzip"}
    with pytest.raises(MediaError) as error:
        await cache.fetch(URI)
    assert not list(cache.root.iterdir())
    assert cache._reserved == 0
    assert KEY.hex() not in str(error.value)


@pytest.mark.asyncio
async def test_literal_ssrf_no_network(cache, network):
    with pytest.raises(MediaError):
        await cache.fetch(URI.replace("files.example.org", "[::1]"))
    assert not network["calls"]


@pytest.mark.parametrize("host,canonical", [
    ("\uff11\uff12\uff17\u3002\uff10\u3002\uff10\u3002\uff11", "127.0.0.1"),
    ("\uff11\uff10\uff0e\uff10\uff0e\uff10\uff0e\uff11", "10.0.0.1"),
    ("192\uff61168.1.1", "192.168.1.1"),
])
@pytest.mark.asyncio
async def test_unicode_normalized_literal_denied_before_connector(cache, monkeypatch, host, canonical):
    uri = URI.replace("files.example.org", host)
    url = URL(parse_uri(uri)[0])
    assert url.raw_host == canonical
    resolver = PublicResolver()
    resolver.resolve = AsyncMock(side_effect=AssertionError("Literal must bypass DNS"))
    connector = aiohttp.TCPConnector(resolver=resolver)
    try:
        # Exercise the real connector's literal-address shortcut, not a fake HTTP session.
        answers = await connector._resolve_host(url.raw_host, url.port)
        assert answers[0]["host"] == canonical
        resolver.resolve.assert_not_awaited()
    finally:
        await connector.close()
    connect = AsyncMock(side_effect=AssertionError("Denied address reached connector"))
    monkeypatch.setattr(aiohttp.TCPConnector, "_create_connection", connect)
    with pytest.raises(MediaError):
        await cache.fetch(uri)
    connect.assert_not_awaited()
    assert not list(cache.root.iterdir())


@pytest.mark.parametrize("punctuation", ["'", '"', "<", ">"])
@pytest.mark.parametrize("scheme", ["aesgcm", "AESGCM", "AeSgCm"])
def test_sanitize_complete_punctuated_token(punctuation, scheme):
    uri = URI.replace("aesgcm", scheme).replace("item", "f" + punctuation + "x")
    assert sanitize("caption " + uri + " tail") == "caption [encrypted attachment] tail"


@pytest.mark.asyncio
async def test_concurrency_ingress_deadline_and_disconnect(cache, network):
    network["gate"] = asyncio.Event()
    tasks = [asyncio.create_task(cache.fetch(URI)) for _ in range(12)]
    await asyncio.sleep(.02)
    assert len(network["calls"]) == 3
    assert len(list(cache.root.glob("*.part"))) == 3
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in cache.root.iterdir())
    assert not list(cache.root.glob("*.png"))
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    await cache.close()
    assert all(t.cancelled() for t in tasks)
    assert not list(cache.root.iterdir())
    assert cache._reserved == 0
    cache.start()
    cache.timeout = .01
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert not list(cache.root.iterdir())
    network["gate"].set()
    assert Path((await cache.fetch(URI))[0]).read_bytes() == PLAIN


@pytest.mark.asyncio
async def test_quota_and_cleanup(cache, network, tmp_path):
    cache.quota = 8191
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert not network["calls"]
    cache.quota = 65536
    path = Path((await cache.fetch(URI))[0])
    outside = tmp_path / "outside"
    outside.write_text("keep")
    (cache.root / "symlink").symlink_to(outside)
    os.utime(path, (0, 0))
    cache.sweep()
    assert not path.exists() and outside.read_text() == "keep"
    await cache.close()
    (cache.root / "unfinished.part").write_bytes(b"secret")
    survivor = cache.root / "existing.pdf"
    survivor.write_bytes(b"%PDF-")
    survivor.chmod(0o644)
    cache.start()
    assert list(cache.root.iterdir()) == [survivor]
    assert stat.S_IMODE(survivor.stat().st_mode) == 0o600
    cache.ttl = .01
    path = Path((await cache.fetch(URI))[0])
    await asyncio.sleep(.05)
    assert not path.exists()


@pytest.mark.asyncio
async def test_entries_see_new_files_with_nonzero_held_offset(cache):
    assert cache._entries() == []
    for name in ("first", "second"):
        (cache.root / name).write_bytes(b"keep")
        os.lseek(cache._fd, 1, os.SEEK_SET)
        assert set(cache._entries()) == ({"first"} if name == "first" else {"first", "second"})
        assert os.lseek(cache._fd, 0, os.SEEK_CUR) == 1


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.asyncio
async def test_entries_close_scan_descriptor(cache, monkeypatch, failure):
    listdir = os.listdir
    scanned = []

    def scan(fd):
        assert fd != cache._fd
        scanned.append(fd)
        if failure:
            raise OSError("scan failed")
        return listdir(fd)

    monkeypatch.setattr(os, "listdir", scan)
    if failure:
        with pytest.raises(OSError, match="scan failed"):
            cache._entries()
    else:
        assert cache._entries() == []
    assert len(scanned) == 1
    with pytest.raises(OSError):
        os.fstat(scanned[0])
    os.fstat(cache._fd)


@pytest.mark.asyncio
async def test_repeated_sweep_and_quota_see_new_files(cache, network):
    for name in ("first", "second"):
        expired = cache.root / name
        expired.write_bytes(b"old")
        os.utime(expired, (0, 0))
        cache.sweep()
        assert not expired.exists()
    cache.quota = 8192
    await cache.fetch(URI)
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert len(network["calls"]) == 1


@pytest.mark.asyncio
async def test_symlink_cache_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    cache = MediaCache(tmp_path / "link" / "cache")
    with pytest.raises(OSError):
        cache.start()
    assert not (target / "cache").exists()


@pytest.mark.parametrize("data,mime", [
    (b"%PDF-1.7", "application/pdf"), (b"ID3abc", "audio/mpeg"),
    (b"RIFFxxxxWAVE", "audio/wav"), (b"RIFFxxxxWEBP", "image/webp"),
    (b"OggSxxxxOpusHead", "audio/ogg"), (b"\0\0\0\x18ftypisom", "video/mp4"),
    (b"\0\0\0\x18ftypavif", "image/avif"), (b"random", "application/octet-stream"),
])
def test_mime_content_not_filename(data, mime):
    assert content_type(data)[0] == mime


@pytest.mark.asyncio
async def test_queued_time_counts_toward_deadline(cache, network):
    network["gate"] = asyncio.Event()
    tasks = [asyncio.create_task(cache.fetch(URI)) for _ in range(3)]
    await asyncio.sleep(.01)
    cache.timeout = .01
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert len(network["calls"]) == 3  # The fourth timed out while still queued.
    await cache.close()
    assert all(t.cancelled() for t in tasks)
    assert not list(cache.root.iterdir())


@pytest.mark.asyncio
async def test_quota_reservations_bound_concurrent_downloads(cache, network):
    cache.quota = 8192
    network["gate"] = asyncio.Event()
    first = asyncio.create_task(cache.fetch(URI))
    await asyncio.sleep(.01)
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert len(network["calls"]) == 1
    first.cancel()
    await asyncio.gather(first, return_exceptions=True)
    assert cache._reserved == 0


@pytest.mark.parametrize("limit,value", [("ttl", 0), ("ttl", float("nan")), ("ttl", float("inf")),
    ("max_bytes", -1), ("quota", 0), ("concurrency", 0)])
def test_invalid_limits(tmp_path, limit, value):
    with pytest.raises(ValueError):
        MediaCache(tmp_path, **{limit: value})


@pytest.mark.asyncio
async def test_name_collision_does_not_unlink_existing(cache, network, monkeypatch):
    from types import SimpleNamespace
    import inbound_media
    existing = cache.root / "collision.part"
    existing.write_bytes(b"keep")
    monkeypatch.setattr(inbound_media.uuid, "uuid4", lambda: SimpleNamespace(hex="collision"))
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert existing.read_bytes() == b"keep"
    assert cache._reserved == 0
    assert not network["calls"]


@pytest.mark.asyncio
async def test_publish_collision_does_not_overwrite(cache, network, monkeypatch, tmp_path):
    from types import SimpleNamespace
    import inbound_media
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    # The symlink is inserted after the pre-download sweep to test publication.
    original_get = aiohttp.ClientSession.get
    def get(self, *args, **kwargs):
        (cache.root / "collision.png").symlink_to(outside)
        return original_get(self, *args, **kwargs)
    monkeypatch.setattr(aiohttp.ClientSession, "get", get)
    names = iter(["temporary", "collision"])
    monkeypatch.setattr(inbound_media.uuid, "uuid4", lambda: SimpleNamespace(hex=next(names)))
    with pytest.raises(MediaError):
        await cache.fetch(URI)
    assert outside.read_bytes() == b"keep"
    assert (cache.root / "collision.png").is_symlink()
    assert not list(cache.root.glob("*.part"))
