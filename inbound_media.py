"""Authenticated XEP-0454 attachments; no remote coordinates leave this module."""
from __future__ import annotations

import asyncio
import ipaddress
import math
import os
import re
import socket
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yarl import URL


class MediaError(Exception):
    """Deliberately contains no attacker-controlled diagnostic data."""


def sanitize(text: str) -> str:
    text = re.sub(r"aesgcm:\S*", "[encrypted attachment]", text, flags=re.I)
    return re.sub(r"data:image/[^\s<>]*", "", text, flags=re.I).strip()


def parse_uri(uri: str) -> tuple[str, bytes, bytes]:
    try:
        parts = urlsplit(uri)
        if (parts.scheme != "aesgcm" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.port not in (None, 443)
                or not re.fullmatch(r"[0-9a-fA-F]{88}", parts.fragment)
                or any(c.isspace() or ord(c) < 32 for c in uri)
                or "\\" in uri or "%" in parts.netloc):
            raise ValueError
        material = bytes.fromhex(parts.fragment)
        return urlunsplit(("https", parts.netloc, parts.path, parts.query, "")), material[:12], material[12:]
    except ValueError:
        raise MediaError("Invalid encrypted attachment") from None


def attachment_uris(body: str, xml, *, sce: bool) -> list[str]:
    """Body-only legacy format, or authenticated SCE OOB/SFS URL sources."""
    lines = body.strip().splitlines()
    if lines and lines[0].startswith("aesgcm://") and (len(lines) == 1 or (
            len(lines) == 2 and lines[1].startswith("data:image/"))):
        return [lines[0]]
    if xml is None:
        return []
    uris = []
    for elem in xml.findall("{jabber:x:oob}x/{jabber:x:oob}url") + xml.findall(
            "{urn:xmpp:sfs:0}file-sharing/{urn:xmpp:sfs:0}sources/"
            "{http://jabber.org/protocol/url-data}url-data"):
        uri = elem.get("target") if elem.tag.endswith("url-data") else elem.text
        if (uri and uri.startswith("aesgcm://") and uri not in uris
                and (sce or uri in lines)):
            uris.append(uri)
    return uris[:4]


def public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not getattr(ip, "ipv4_mapped", None)
            and not (isinstance(ip, ipaddress.IPv6Address) and (ip.sixtofour or ip.teredo)))


class PublicResolver(aiohttp.abc.AbstractResolver):
    """The connector uses exactly these checked answers, never a second lookup."""

    async def resolve(self, host, port=443, family=socket.AF_UNSPEC):
        answers = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM)
        if not answers or any(not public_address(a[4][0]) for a in answers):
            raise MediaError("Attachment host denied")
        return [dict(hostname=host, host=a[4][0], port=port, family=a[0],
                     proto=a[2], flags=socket.AI_NUMERICHOST) for a in answers]

    async def close(self):
        pass


def content_type(data: bytes) -> tuple[str, str]:
    for signature, mime, suffix in (
        (b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
        (b"\xff\xd8\xff", "image/jpeg", ".jpg"),
        (b"GIF87a", "image/gif", ".gif"), (b"GIF89a", "image/gif", ".gif"),
        (b"%PDF-", "application/pdf", ".pdf"),
        (b"fLaC", "audio/flac", ".flac"), (b"ID3", "audio/mpeg", ".mp3"),
        (b"PK\x03\x04", "application/zip", ".zip"),
    ):
        if data.startswith(signature):
            return mime, suffix
    if data.startswith(b"RIFF"):
        if data[8:12] == b"WEBP":
            return "image/webp", ".webp"
        if data[8:12] == b"WAVE":
            return "audio/wav", ".wav"
        if data[8:12] == b"AVI ":
            return "video/x-msvideo", ".avi"
    if data.startswith(b"OggS"):
        return ("audio/ogg", ".ogg") if b"OpusHead" in data or b"\x01vorbis" in data else ("application/ogg", ".ogg")
    if data[4:8] == b"ftyp":
        if data[8:12] in (b"avif", b"avis"):
            return "image/avif", ".avif"
        if data[8:12] in (b"M4A ", b"M4B "):
            return "audio/mp4", ".m4a"
        if data[8:12] in (b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"M4V "):
            return "video/mp4", ".mp4"
    if data.startswith(b"\x1aE\xdf\xa3") and b"webm" in data[:128]:
        return "video/webm", ".webm"
    return "application/octet-stream", ".bin"


class MediaCache:
    def __init__(self, root: Path, *, ttl=86400, max_bytes=25 * 1024 * 1024,
                 quota=256 * 1024 * 1024, concurrency=3, timeout=60):
        self.root = root.absolute()
        self.ttl, self.max_bytes, self.quota = ttl, max_bytes, quota
        self.timeout = timeout
        if (not all(math.isfinite(v) and v > 0 for v in (ttl, max_bytes, quota, timeout))
                or concurrency < 1):
            raise ValueError("Invalid inbound media limits")
        self._slots = asyncio.Semaphore(concurrency)
        self._active: set[asyncio.Task] = set()
        self._sweeper = None
        self._fd = None
        self._reserved = 0
        self._closed = True
        self._temps = set()

    def start(self):
        if not self._closed:
            return
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in self.root.parts[1:]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except BaseException:
            os.close(fd)
            raise
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            os.close(fd)
            raise MediaError("Unsafe attachment cache")
        os.fchmod(fd, 0o700)
        self._fd = fd
        self._closed = False
        try:
            self.sweep(startup=True)
        except BaseException:
            os.close(fd)
            self._fd = None
            self._closed = True
            raise
        self._sweeper = asyncio.create_task(self._sweep_loop())

    def _entries(self):
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._fd)
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    def sweep(self, *, startup=False):
        for name in self._entries():
            if name in self._temps:
                continue
            try:
                info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            except FileNotFoundError:
                continue  # Hermes may have rehomed this entry.
            if (not stat.S_ISREG(info.st_mode) or (startup and name.endswith(".part"))
                    or time.time() - info.st_mtime >= self.ttl):
                if not stat.S_ISDIR(info.st_mode):
                    try:
                        os.unlink(name, dir_fd=self._fd)
                    except FileNotFoundError:
                        pass
            elif startup:
                os.chmod(name, 0o600, dir_fd=self._fd, follow_symlinks=False)

    async def _sweep_loop(self):
        while True:
            await asyncio.sleep(min(300, self.ttl))
            try:
                self.sweep()
            except OSError:
                # Retry next sweep without logging filesystem or remote secrets.
                pass

    async def close(self):
        self._closed = True
        tasks = list(self._active)
        if self._sweeper:
            tasks.append(self._sweeper)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._sweeper = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    async def fetch(self, uri: str) -> tuple[str, str]:
        if self._closed:
            raise MediaError("Attachment unavailable")
        # Refuse excess ingress rather than accumulate unbounded semaphore waiters.
        if len(self._active) >= 12:
            raise MediaError("Attachment busy")
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with asyncio.timeout(self.timeout):
                async with self._slots:
                    return await self._fetch(uri)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise MediaError("Attachment unavailable") from None
        finally:
            self._active.discard(task)

    async def _fetch(self, uri):
        url, iv, key = parse_uri(uri)
        # Validate the same canonical host aiohttp uses, including IDNA normalization.
        url = URL(url)
        host = url.raw_host
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        # aiohttp bypasses its resolver for literals, so validate them here.
        if literal is not None and not public_address(str(literal)):
            raise MediaError("Attachment host denied")
        self.sweep()
        entries = self._entries()
        if len(entries) >= 1024:
            raise MediaError("Attachment cache full")
        used = 0
        for name in entries:
            try:
                used += os.stat(name, dir_fd=self._fd, follow_symlinks=False).st_size
            except FileNotFoundError:
                pass
        reservation = 2 * self.max_bytes
        if used + self._reserved + reservation > self.quota:
            raise MediaError("Attachment cache full")
        self._reserved += reservation
        name = uuid.uuid4().hex + ".part"
        created = False
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self._fd)
            created = True
            self._temps.add(name)
            with os.fdopen(fd, "wb") as output:
                decryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).decryptor()
                tail, size, header = b"", 0, b""
                connector = aiohttp.TCPConnector(resolver=PublicResolver(), use_dns_cache=False)
                async with aiohttp.ClientSession(connector=connector, trust_env=False,
                        cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    async with session.get(url, allow_redirects=False) as response:
                        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                            raise MediaError("Attachment download failed")
                        if response.content_length is not None and response.content_length > self.max_bytes:
                            raise MediaError("Attachment too large")
                        async for chunk in response.content.iter_chunked(65536):
                            size += len(chunk)
                            if size > self.max_bytes:
                                raise MediaError("Attachment too large")
                            tail += chunk
                            if len(tail) > 16:
                                plain = decryptor.update(tail[:-16])
                                header = (header + plain)[:8192]
                                output.write(plain)
                                tail = tail[-16:]
                if len(tail) != 16:
                    raise MediaError("Attachment authentication failed")
                output.write(decryptor.finalize_with_tag(tail))
                output.flush()
                os.fsync(output.fileno())
            os.utime(name, None, dir_fd=self._fd, follow_symlinks=False)
            mime, suffix = content_type(header)
            final = uuid.uuid4().hex + suffix
            # Exclusive hard-link publication is atomic and cannot overwrite a symlink.
            os.link(name, final, src_dir_fd=self._fd, dst_dir_fd=self._fd, follow_symlinks=False)
            return str(self.root / final), mime
        finally:
            self._reserved -= reservation
            self._temps.discard(name)
            if created:
                try:
                    os.unlink(name, dir_fd=self._fd)
                except FileNotFoundError:
                    pass
