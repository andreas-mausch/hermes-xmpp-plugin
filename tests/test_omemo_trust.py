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
DEVICE = "/devices/alice@example.org/1001/identity_key"
TRUST = "/trust/alice@example.org/" + BASE


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "store.json"
    path.write_text(json.dumps({DEVICE: BASE, TRUST: "UNDECIDED", "/secret": "DO_NOT_DISPLAY"}))
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
    assert invoke(store, "list", "--jid", "alice@example.org") == 0
    out = capsys.readouterr()
    assert "1001\tUNDECIDED\t09000000" in out.out
    assert "DO_NOT_DISPLAY" not in out.out + out.err
    assert "snapshot" in out.err and "ALL writers" in out.err
    assert invoke(store, "list", "--jid", "bob@example.org") == 0
    assert "1001" not in capsys.readouterr().out


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
    assert json.loads(store.read_text()) == {DEVICE: BASE, TRUST: grade, "/secret": "DO_NOT_DISPLAY"}
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
    lambda s: s.pop(DEVICE), lambda s: s.pop(TRUST),
    lambda s: s.update({TRUST: "UNKNOWN"}), lambda s: s.update({TRUST: []}),
    lambda s: s.update({DEVICE: "not-a-key"}),
    lambda s: s.update({DEVICE: base64.urlsafe_b64encode(bytes(32)).decode()}),
    lambda s: s.update({"/devices/alice@example.org/0/identity_key": BASE}),
    lambda s: s.update({"/devices/alice@example.org/bad": BASE}),
])
def test_invalid_entries_no_writes(store, change):
    data = json.loads(store.read_text())
    change(data)
    store.write_text(json.dumps(data))
    before = store.read_bytes()
    assert invoke(store, *mutation()) == 1
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


def test_fingerprint_mismatch(store):
    before = store.read_bytes()
    assert invoke(store, *mutation(fingerprint="00" * 32)) == 1
    assert store.read_bytes() == before
    assert len(list(store.parent.iterdir())) == 1


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
