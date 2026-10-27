import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

import pytest

import omemo_trust as cli


BASE = "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY="
FP = "09" + "00" * 31
GROUPED_FP = "09000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000"
DEVICE = "/devices/alice@example.org/1001/identity_key"
TRUST = "/trust/alice@example.org/" + BASE
LIST = "/devices/alice@example.org/list"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "store.json"
    path.write_text(json.dumps({
        DEVICE: BASE, TRUST: "UNDECIDED", LIST: [1001, 2147483647],
        "/devices/bob@example.org/list": [],
        "/devices/alice@example.org/1001/namespaces": ["eu.siacs.conversations.axolotl"],
        "/devices/alice@example.org/1001/active": {"eu.siacs.conversations.axolotl": True},
        "/devices/alice@example.org/1001/label": None,
        "/own_device_id": 1001, "/secret": "DO_NOT_DISPLAY",
        "/sessions/alice@example.org/1001": {"state": "DO_NOT_DISPLAY"},
    }))
    path.chmod(0o640)
    return path


def invoke(store, *args):
    return cli.main(["--store", str(store), *args])


def mutation(command="trust", fingerprint=FP):
    args = [command, "--jid", "alice@example.org", "--device-id", "1001", "--offline"]
    if command == "trust":
        args += ["--fingerprint", fingerprint]
    return args


@pytest.mark.parametrize("public,expected", [
    (BASE, FP),
    # RFC 8032 test 1 public key, converted Curve25519 public vector.
    (base64.urlsafe_b64encode(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")).decode(),
     "D85E07EC22B0AD881537C2F44D662D1A143CF830C57ACA4305D85C7A90F6B62E"),
])
def test_public_vectors(public, expected):
    assert cli.fingerprint(public) == expected
    assert cli.fingerprint(public.rstrip("=")) == expected


def test_list_snapshot_filter(store, capsys):
    before = store.read_bytes()
    assert invoke(store, "list", "--jid", "alice@example.org") == 0
    out = capsys.readouterr()
    assert out.out == (
        "JID                DEVICE_ID  TRUST      FINGERPRINT\n"
        f"alice@example.org  1001       UNDECIDED  {GROUPED_FP}\n"
    )
    assert "DO_NOT_DISPLAY" not in out.out + out.err
    assert out.err == (
        "Warning: offline snapshot only; live reads may be incomplete or stale. "
        + cli.OFFLINE_WARNING + "\n"
    )
    assert invoke(store, "list", "--jid", "bob@example.org") == 0
    assert capsys.readouterr().out == "JID  DEVICE_ID  TRUST  FINGERPRINT\n"
    assert store.read_bytes() == before


def test_list_sorts_device_ids_numerically_within_jid(store, capsys):
    data = json.loads(store.read_text())
    for bare, device in [("bob@example.org", "2"), ("alice@example.org", "10"),
                         ("alice@example.org", "2"), ("bob@example.org", "1")]:
        data[f"/devices/{bare}/{device}/identity_key"] = BASE
    store.write_text(json.dumps(data))

    assert invoke(store, "list") == 0
    rows = [line.split()[:2] for line in capsys.readouterr().out.splitlines()[1:]]
    assert rows == [["alice@example.org", "2"], ["alice@example.org", "10"],
                    ["alice@example.org", "1001"], ["bob@example.org", "1"],
                    ["bob@example.org", "2"]]


@pytest.mark.parametrize("bare,expected", [
    (None, [
        "JID                           DEVICE_ID   TRUST            FINGERPRINT",
        "a@b                           2           MISSING          ",
        "a@b                           10          MISSING          ",
        "long.person@long.example.org  2147483647  BLINDLY_TRUSTED  ",
        "mid@example.org               123         TRUSTED          ",
    ]),
    ("a@b", [
        "JID  DEVICE_ID  TRUST    FINGERPRINT",
        "a@b  2          MISSING  ",
        "a@b  10         MISSING  ",
    ]),
    ("mid@example.org", [
        "JID              DEVICE_ID  TRUST    FINGERPRINT",
        "mid@example.org  123        TRUSTED  ",
    ]),
    ("absent@example.org", ["JID  DEVICE_ID  TRUST  FINGERPRINT"]),
])
def test_list_column_widths_use_only_shown_rows(store, capsys, bare, expected):
    store.write_text(json.dumps({
        "/devices/long.person@long.example.org/2147483647/identity_key": BASE,
        "/trust/long.person@long.example.org/" + BASE: "BLINDLY_TRUSTED",
        "/devices/a@b/10/identity_key": BASE,
        "/devices/a@b/2/identity_key": BASE,
        "/devices/mid@example.org/123/identity_key": BASE,
        "/trust/mid@example.org/" + BASE: "TRUSTED",
    }))
    assert invoke(store, "list", *([] if bare is None else ["--jid", bare])) == 0
    assert capsys.readouterr().out == "\n".join(
        line + GROUPED_FP if index else line for index, line in enumerate(expected)
    ) + "\n"


def test_list_empty_store_headers(store, capsys):
    store.write_text("{}")
    assert invoke(store, "list") == 0
    assert capsys.readouterr().out == "JID  DEVICE_ID  TRUST  FINGERPRINT\n"


@pytest.mark.parametrize("command,grade", [("trust", "TRUSTED"), ("distrust", "DISTRUSTED")])
def test_mutation_backup_atomic(store, monkeypatch, capsys, command, grade):
    raw = store.read_bytes()
    before = store.stat()
    replace = os.replace
    calls = []

    def checked(source, target):
        assert Path(source).parent == store.parent
        assert store.read_bytes() == raw
        assert json.loads(Path(source).read_text())[TRUST] == grade
        calls.append((source, target))
        replace(source, target)

    monkeypatch.setattr(cli.os, "replace", checked)
    assert invoke(store, *mutation(command, " ".join(FP.lower()[i:i+8] for i in range(0, 64, 8)))) == 0
    assert len(calls) == 1
    expected = json.loads(raw)
    expected[TRUST] = grade
    assert json.loads(store.read_text()) == expected
    after = store.stat()
    assert stat.S_IMODE(after.st_mode) == 0o640
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    backups = list(store.parent.glob("store.json.backup-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == raw
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert backups[0].stat().st_uid == before.st_uid
    assert not list(store.parent.glob("*.tmp-*"))
    assert "DO_NOT_DISPLAY" not in capsys.readouterr().out


@pytest.mark.parametrize("args", [
    [], ["unknown"], ["trust"],
    [arg for arg in mutation() if arg != "--offline"],
    mutation(fingerprint="00"), mutation(fingerprint="G" * 64),
    mutation(fingerprint=FP + "\t"),
    ["distrust", "--jid", "alice@example.org/resource", "--device-id", "1001", "--offline"],
    ["distrust", "--jid", "alice@example.org", "--device-id", "0", "--offline"],
    ["distrust", "--jid", "alice@example.org", "--device-id", "01", "--offline"],
    ["distrust", "--jid", "alice@example.org", "--device-id", "2147483648", "--offline"],
])
def test_parser_rejects_without_writes(store, args):
    before = store.read_bytes()
    with pytest.raises(SystemExit) as exc:
        invoke(store, *args)
    assert exc.value.code == 2
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


@pytest.mark.parametrize("change", [
    lambda s: s.pop(DEVICE),
    lambda s: s.update({TRUST: "UNKNOWN"}), lambda s: s.update({TRUST: []}),
    lambda s: s.update({DEVICE: "not-a-key"}),
    lambda s: s.update({DEVICE: base64.urlsafe_b64encode(bytes(32)).decode()}),
    lambda s: s.update({"/devices/alice@example.org/0/identity_key": BASE}),
    lambda s: s.update({"/devices/alice@example.org/bad": BASE}),
    lambda s: s.update({"/devices//list": []}),
    lambda s: s.update({"/devices/alice@example.org/list/extra": []}),
    lambda s: s.update({"/devices/alice@example.org/list/": []}),
])
def test_invalid_entries_no_writes(store, change):
    data = json.loads(store.read_text())
    change(data)
    store.write_text(json.dumps(data))
    before = store.read_bytes()
    assert invoke(store, *mutation()) == 1
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


@pytest.mark.parametrize("value", [None, {}, "1001", 1001, [True], [False], ["1001"],
                                  [1.0], [None], [[]], [0], [-1], [2147483648]])
@pytest.mark.parametrize("command", ["list", "trust", "distrust"])
def test_invalid_device_list_no_writes(store, value, command):
    data = json.loads(store.read_text())
    data[LIST] = value
    store.write_text(json.dumps(data))
    before = store.read_bytes()
    assert invoke(store, *(["list"] if command == "list" else mutation(command))) == 1
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


@pytest.mark.parametrize("value", [[], [1], [2147483647], [1001, 2]])
def test_valid_device_lists(store, value):
    data = json.loads(store.read_text())
    data[LIST] = value
    store.write_text(json.dumps(data))
    assert invoke(store, "list") == 0


def test_fingerprint_mismatch(store):
    before = store.read_bytes()
    assert invoke(store, *mutation(fingerprint="00" * 32)) == 1
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


@pytest.mark.parametrize("command,grade", [("trust", "TRUSTED"), ("distrust", "DISTRUSTED")])
def test_known_identity_without_trust_entry(store, command, grade):
    data = json.loads(store.read_text())
    del data[TRUST]
    store.write_text(json.dumps(data))
    assert invoke(store, *mutation(command)) == 0
    data[TRUST] = grade
    assert json.loads(store.read_text()) == data


@pytest.mark.parametrize("raw", ["[]", "null", '{"devices": {}}', '{"/a":1,"/a":2}', '{"/a": NaN}', "{", "\udcff"])
def test_bad_json(store, raw, capsys):
    store.write_bytes(raw.encode("utf-8", errors="surrogatepass"))
    before = store.read_bytes()
    assert invoke(store, "list") == 1
    assert "Error:" in capsys.readouterr().err
    assert store.read_bytes() == before


def test_symlink_and_missing(store, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(store)
    assert invoke(link, *mutation()) == 1
    assert invoke(tmp_path / "missing", "list") == 1
    assert json.loads(store.read_text())[TRUST] == "UNDECIDED"


def test_replace_failure(store, monkeypatch):
    before = store.read_bytes()
    def fail(*args):
        raise OSError("simulated replacement failure")
    monkeypatch.setattr(cli.os, "replace", fail)
    assert invoke(store, *mutation()) == 1
    assert store.read_bytes() == before
    assert not list(store.parent.glob("*.tmp-*"))
    assert list(store.parent.glob("*.backup-*"))[0].read_bytes() == before


def test_owner_required(store, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: store.stat().st_uid + 1)
    assert invoke(store, *mutation()) == 1
    assert len(list(store.parent.iterdir())) == 1


def test_detect_changed_store(store, monkeypatch, capsys):
    original = store.read_bytes()
    changed = original + b"\n"
    fsync = os.fsync
    calls = 0

    def change_after_sync(fd):
        nonlocal calls
        fsync(fd)
        calls += 1
        if calls == 2:
            store.write_bytes(changed)

    monkeypatch.setattr(cli.os, "fsync", change_after_sync)
    assert invoke(store, *mutation()) == 1
    assert "store changed" in capsys.readouterr().err
    assert store.read_bytes() == changed
    assert list(store.parent.glob("*.backup-*"))[0].read_bytes() == original
    assert not list(store.parent.glob("*.tmp-*"))


def test_temp_sync_failure(store, monkeypatch):
    original = store.read_bytes()
    calls = 0
    fsync = os.fsync

    def fail_second_sync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated sync failure")
        fsync(fd)

    monkeypatch.setattr(cli.os, "fsync", fail_second_sync)
    assert invoke(store, *mutation()) == 1
    assert store.read_bytes() == original
    assert not list(store.parent.glob("*.tmp-*"))
    assert list(store.parent.glob("*.backup-*"))[0].read_bytes() == original


def test_defaults(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.delenv("XMPP_OMEMO_STORAGE_PATH", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cli.default_store() == tmp_path / ".hermes/xmpp_omemo.json"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    assert cli.default_store() == tmp_path / "profile/xmpp_omemo.json"
    monkeypatch.setitem(sys.modules, "hermes_constants", types.SimpleNamespace(get_hermes_home=lambda: tmp_path / "context"))
    assert cli.default_store() == tmp_path / "context/xmpp_omemo.json"
    monkeypatch.setenv("XMPP_OMEMO_STORAGE_PATH", "relative.json")
    assert cli.default_store() == Path("relative.json")


def test_module_entrypoint_and_explicit_override(store):
    result = subprocess.run([sys.executable, "-m", "omemo_trust", "--store", str(store), "list"],
                            env={**os.environ, "XMPP_OMEMO_STORAGE_PATH": "/missing"}, capture_output=True, text=True)
    assert result.returncode == 0 and "UNDECIDED" in result.stdout


def test_missing_dependency(store, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "xeddsa", None)
    assert invoke(store, "list") == 1
    assert "optional OMEMO dependencies" in capsys.readouterr().err
