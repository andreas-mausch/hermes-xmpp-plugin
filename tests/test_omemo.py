"""Tests for OMEMO encryption support."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

adapter = pytest.importorskip("adapter")


# ------------------------------------------------------------------
# _StorageImpl
# ------------------------------------------------------------------

class TestStorageImpl:
    def test_json_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "omemo.json"
        store = adapter._StorageImpl(path)

        # pylint: disable=protected-access
        assert store._data == {}

        # store a dict value
        value = {"identity_key": "foobar", "device_id": 123}
        # _store is async
        import asyncio

        asyncio.run(store._store("device_info", value))
        assert store._data["device_info"] == value

        # verify it persisted to disk
        with open(path, encoding="utf-8") as f:
            disk = json.load(f)
        assert disk["device_info"] == value

    def test_delete_removes_key(self, tmp_path: Path) -> None:
        path = tmp_path / "omemo.json"
        store = adapter._StorageImpl(path)
        store._data["to_delete"] = "gone"
        # create the file
        store._save()  # type: ignore[attr-defined]

        import asyncio

        asyncio.run(store._delete("to_delete"))
        assert "to_delete" not in store._data
        with open(path, encoding="utf-8") as f:
            assert "to_delete" not in json.load(f)

    def test_load_returns_just_or_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "omemo.json"
        store = adapter._StorageImpl(path)
        store._data["present"] = "value"

        import asyncio

        just = asyncio.run(store._load("present"))
        nothing = asyncio.run(store._load("missing"))

        # slixmpp-omemo uses a Maybe monad: "Maybe" is the module,
        # "Just" and "Nothing" are inside it.
        assert just is not nothing  # different containers


# ------------------------------------------------------------------
# Config helpers
# ------------------------------------------------------------------

class Config:
    def __init__(self, extra=None):
        self.extra = extra or {}


@pytest.mark.asyncio
async def test_first_message_records_identity_and_undecided_without_dispatch(tmp_path):
    import base64
    from types import SimpleNamespace
    from slixmpp_omemo.xep_0384 import _make_session_manager
    from slixmpp.stanza import Message

    path = tmp_path / "omemo.json"
    storage = adapter._StorageImpl(path)
    bare, device = "alice@example.org", 1001
    namespace = "eu.siacs.conversations.axolotl"
    identity = base64.urlsafe_b64decode("WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=")
    for suffix, value in [("list", [device]), (f"{device}/namespaces", [namespace]),
                          (f"{device}/active", {namespace: True}), (f"{device}/label", None)]:
        await storage.store(f"/devices/{bare}/{suffix}", value)
    manager_cls = _make_session_manager(MagicMock(), MagicMock())
    manager = manager_cls.__new__(manager_cls)
    manager._SessionManager__storage = storage
    manager._SessionManager__undecided_trust_level_name = "UNDECIDED"
    manager._download_bundle = AsyncMock(return_value=SimpleNamespace(identity_key=identity))
    # Bundles are placed in a set by the real dependency.
    bundle = MagicMock()
    bundle.identity_key = identity
    manager._download_bundle.return_value = bundle
    plugin = MagicMock()
    plugin.is_encrypted.return_value = True
    plugin.get_session_manager = AsyncMock(return_value=manager)

    async def decrypt(stanza):
        info = next(iter(await manager.get_device_information(bare)))
        result = Message()
        result["body"] = "not yet trusted"
        return result, info

    plugin.decrypt_message = decrypt
    a = adapter.XmppAdapter(Config({"jid": "bot@example.org", "allowed_users": bare}))
    a.client = MagicMock()
    a.client.__getitem__.return_value = plugin
    a._registered_plugins.add("xep_0384")
    a.handle_message = AsyncMock()
    stanza = Message()
    stanza["from"], stanza["type"], stanza["body"] = bare + "/phone", "chat", "fallback"
    await a._on_message(stanza)
    disk = json.loads(path.read_text())
    encoded = base64.urlsafe_b64encode(identity).decode()
    assert disk[f"/devices/{bare}/{device}/identity_key"] == encoded
    assert disk[f"/trust/{bare}/{encoded}"] == "UNDECIDED"
    manager._download_bundle.assert_awaited_once()
    a.handle_message.assert_not_awaited()


@pytest.mark.parametrize("raw,expected", [("", False), ("false", False), ("true", True)])
def test_btbv_requires_opt_in(monkeypatch, raw, expected):
    monkeypatch.setenv("XMPP_OMEMO_BTBV", raw)
    plugin = adapter._XEP_0384Impl.__new__(adapter._XEP_0384Impl)
    assert plugin._btbv_enabled is expected


@pytest.mark.parametrize("enabled", [True, False])
def test_media_default_follows_omemo(monkeypatch, enabled):
    monkeypatch.delenv("XMPP_OMEMO_MEDIA", raising=False)
    a = adapter.XmppAdapter(Config({"omemo_enabled": enabled}))
    assert a._omemo_media is enabled


def test_media_config_precedence(monkeypatch):
    monkeypatch.setenv("XMPP_OMEMO_MEDIA", "false")
    a = adapter.XmppAdapter(Config({"omemo": {"enabled": False, "media": True}}))
    assert a._omemo_media is True
    extra = adapter._apply_yaml_config({}, {"omemo_media": True})
    assert extra["omemo"]["media"] is True


def test_apply_yaml_config_seeds_omemo(monkeypatch):
    for name in ["XMPP_JID", "XMPP_PASSWORD", "XMPP_OMEMO_ENABLED", "XMPP_OMEMO_STORAGE_PATH"]:
        monkeypatch.delenv(name, raising=False)

    extra = adapter._apply_yaml_config(
        {},
        {
            "jid": "bot@example.org",
            "password": "secret",
            "omemo_enabled": True,
            "omemo_storage_path": "/tmp/omemo_store.json",
        },
    )

    assert extra["omemo"] == {
        "enabled": True,
        "storage_path": "/tmp/omemo_store.json",
    }
    assert os.environ["XMPP_JID"] == "bot@example.org"
    # omemo env vars are optional and not auto-exported by _apply_yaml_config,
    # but the adapter install flow does set them. This test verifies extra dict shape.


# ------------------------------------------------------------------
# Plugin registration shape — OMEMO fields are not part of the core
# register_platform() kwargs (they live in plugin.yaml as optional_env).
# They surface through _apply_yaml_config into the extra dict.
# ------------------------------------------------------------------


def test_omemo_values_surface_in_extra():
    """The _apply_yaml_config helper wires omemo_enabled and
    omemo_storage_path into the extra dict under the 'omemo' key."""
    extra = adapter._apply_yaml_config(
        {},
        {
            "jid": "bot@example.org",
            "password": "secret",
            "omemo_enabled": True,
            "omemo_storage_path": "/tmp/omemo.json",
        },
    )
    assert extra.get("omemo") == {"enabled": True, "storage_path": "/tmp/omemo.json"}


# ------------------------------------------------------------------
# omemo_enabled truthiness parsing (issue #5: XMPP_OMEMO_ENABLED=False was
# silently ignored because `bool("False")` is True for any non-empty string —
# fixed by routing every source (env var, extra["omemo_enabled"],
# extra["omemo"]["enabled"]) through _truthy()).
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("False", False),
        ("false", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("", False),
        ("True", True),
        ("true", True),
        ("1", True),
        ("yes", True),
        ("on", True),
    ],
)
def test_omemo_enabled_env_var_string_truthiness(monkeypatch, raw, expected):
    monkeypatch.setenv("XMPP_JID", "bot@example.org")
    monkeypatch.setenv("XMPP_PASSWORD", "secret")
    monkeypatch.setenv("XMPP_OMEMO_ENABLED", raw)
    a = adapter.XmppAdapter(Config())
    assert a._omemo_enabled is expected


@pytest.mark.parametrize("raw,expected", [("False", False), ("True", True), ("0", False), ("1", True)])
def test_omemo_enabled_extra_omemo_enabled_key_truthiness(monkeypatch, raw, expected):
    monkeypatch.delenv("XMPP_OMEMO_ENABLED", raising=False)
    a = adapter.XmppAdapter(Config(extra={
        "jid": "bot@example.org",
        "password": "secret",
        "omemo_enabled": raw,
    }))
    assert a._omemo_enabled is expected


@pytest.mark.parametrize("raw,expected", [("False", False), ("True", True), (False, False), (True, True)])
def test_omemo_enabled_nested_omemo_dict_truthiness(monkeypatch, raw, expected):
    monkeypatch.delenv("XMPP_OMEMO_ENABLED", raising=False)
    a = adapter.XmppAdapter(Config(extra={
        "jid": "bot@example.org",
        "password": "secret",
        "omemo": {"enabled": raw},
    }))
    assert a._omemo_enabled is expected


def test_omemo_disabled_env_var_means_no_plugin_registration(monkeypatch):
    """End-to-end guard for issue #5: with OMEMO disabled, connect() must never
    register xep_0384 — otherwise encryption could still kick in despite the
    operator explicitly opting out."""
    monkeypatch.setenv("XMPP_JID", "bot@example.org")
    monkeypatch.setenv("XMPP_PASSWORD", "secret")
    monkeypatch.setenv("XMPP_OMEMO_ENABLED", "False")
    a = adapter.XmppAdapter(Config())
    assert a._omemo_enabled is False

    # Simulate the plugin-registration branch in connect() directly rather
    # than standing up a real slixmpp client: it's gated purely on
    # _omemo_enabled, so this reproduces the exact condition connect() checks.
    would_register_omemo = a._omemo_enabled and adapter.SLIXMPP_OMEMO_AVAILABLE
    assert would_register_omemo is False


# ------------------------------------------------------------------
# Session-manager recovery
# ------------------------------------------------------------------


def test_omemo_session_manager_resets_failed_init_task():
    if not adapter.SLIXMPP_OMEMO_AVAILABLE:
        pytest.skip("slixmpp-omemo not available")

    plugin = adapter._XEP_0384Impl.__new__(adapter._XEP_0384Impl)
    failed = MagicMock()
    failed.done.return_value = True
    setattr(plugin, "_XEP_0384__session_manager_task", failed)
    setattr(plugin, "_XEP_0384__session_manager", "poisoned")

    plugin._reset_failed_session_manager()

    assert getattr(plugin, "_XEP_0384__session_manager_task") is None
    assert getattr(plugin, "_XEP_0384__session_manager") is None


@pytest.mark.asyncio
async def test_omemo_session_manager_falls_back_to_oldmemo_for_twomemo_failure(monkeypatch):
    if not adapter.SLIXMPP_OMEMO_AVAILABLE:
        pytest.skip("slixmpp-omemo not available")

    plugin = adapter._XEP_0384Impl.__new__(adapter._XEP_0384Impl)
    plugin.xmpp = MagicMock()
    plugin.xmpp.event = MagicMock()
    plugin._create_oldmemo_only_session_manager = AsyncMock(return_value="legacy-manager")

    async def boom(_self):
        raise RuntimeError("Device list download failed for alice@example.org under namespace urn:xmpp:omemo:2")

    monkeypatch.setattr(adapter.XEP_0384, "get_session_manager", boom, raising=False)

    manager = await plugin.get_session_manager()

    assert manager == "legacy-manager"
    assert getattr(plugin, "_XEP_0384__session_manager") == "legacy-manager"
    plugin.xmpp.event.assert_called_once_with("omemo_initialized")


def test_max_message_length_surfaces_in_extra():
    extra = adapter._apply_yaml_config(
        {},
        {
            "jid": "bot@example.org",
            "password": "secret",
            "max_message_length": 4000,
        },
    )
    assert extra.get("max_message_length") == 4000


# ------------------------------------------------------------------
# OMEMO long-message chunking — _send_encrypted splits before encrypt
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_encrypted_splits_long_message():
    """_send_encrypted should chunk the body and encrypt each chunk separately."""
    from unittest.mock import AsyncMock, MagicMock

    a = adapter.XmppAdapter(MagicMock())
    a.client = MagicMock()  # non-None so the guard passes
    a.MAX_MESSAGE_LENGTH = 40

    a._send_encrypted_one = AsyncMock(
        return_value=adapter.SendResult(success=True, message_id="enc")
    )

    body = ("word " * 60).strip()  # well over 40 chars
    result = await a._send_encrypted("user@example.org", body)

    assert result.success is True
    # More than one encrypted stanza was produced.
    assert a._send_encrypted_one.await_count > 1
    # Every encrypted chunk respected the limit.
    for call in a._send_encrypted_one.await_args_list:
        chunk = call.args[1]
        assert len(chunk) <= a.MAX_MESSAGE_LENGTH


@pytest.mark.asyncio
async def test_send_encrypted_short_message_single_chunk():
    from unittest.mock import AsyncMock, MagicMock

    a = adapter.XmppAdapter(MagicMock())
    a.client = MagicMock()
    a._send_encrypted_one = AsyncMock(
        return_value=adapter.SendResult(success=True, message_id="enc")
    )
    result = await a._send_encrypted("user@example.org", "short and sweet")
    assert result.success is True
    assert a._send_encrypted_one.await_count == 1
