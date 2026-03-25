import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

# Provide minimal hvac stub for offline test environments.
hvac_stub = types.ModuleType("hvac")
hvac_exceptions_stub = types.ModuleType("hvac.exceptions")


class _InvalidPath(Exception):
    pass


class _VaultError(Exception):
    pass


hvac_exceptions_stub.InvalidPath = _InvalidPath
hvac_exceptions_stub.VaultError = _VaultError
hvac_stub.exceptions = hvac_exceptions_stub
hvac_stub.Client = object
sys.modules.setdefault("hvac", hvac_stub)
sys.modules.setdefault("hvac.exceptions", hvac_exceptions_stub)

import idrac_password_rotator as rot




class StubVault:
    def __init__(self, read_pw="OldPass!234", fail_write=False):
        self.read_pw = read_pw
        self.fail_write = fail_write
        self.writes = []

    def read_password(self, path: str) -> str:
        return self.read_pw

    def write_password(self, path: str, new_password: str) -> None:
        if self.fail_write:
            raise ValueError("vault write failed")
        self.writes.append((path, new_password))


def mk_record() -> rot.ServerRecord:
    return rot.ServerRecord(
        idrac_host="10.0.0.1",
        idrac_username="root",
        current_password_vault_path="idrac/a/current",
        target_account_username="root",
        target_account_id="2",
        new_password_vault_path="idrac/a/current",
        site="dc1",
        environment="prod",
    )


def test_csv_validation_duplicate_host(tmp_path: Path) -> None:
    p = tmp_path / "in.csv"
    p.write_text(
        "idrac_host,idrac_username,current_password_vault_path,target_account_username,target_account_id,new_password_vault_path,site,environment\n"
        "h1,root,a,root,2,b,dc1,prod\n"
        "h1,root,a,root,2,b,dc1,prod\n",
        encoding="utf-8",
    )
    with pytest.raises(rot.CsvValidationError):
        rot.parse_csv(p)


def test_password_policy() -> None:
    pw = rot.generate_password(length=18)
    assert len(pw) == 18
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)


def test_success_flow() -> None:
    def fake_runner(*args, **kwargs):
        return rot.subprocess.CompletedProcess(args=[], returncode=0, stdout="OK", stderr="")

    record = mk_record()
    vault = StubVault()
    result = rot.process_one_server(
        record=record,
        dry_run=False,
        timeout_seconds=5,
        password_length=16,
        password_specials="!@#",
        vault_client=vault,
        racadm_runner=fake_runner,
    )
    assert result.status == "SUCCESS"
    assert result.idrac_password_changed
    assert result.vault_updated
    assert len(vault.writes) == 1


def test_racadm_failure_flow() -> None:
    def fake_runner(*args, **kwargs):
        return rot.subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="ERROR")

    record = mk_record()
    vault = StubVault()
    result = rot.process_one_server(
        record=record,
        dry_run=False,
        timeout_seconds=5,
        password_length=16,
        password_specials="!@#",
        vault_client=vault,
        racadm_runner=fake_runner,
    )
    assert result.status == "FAILED"
    assert not result.vault_updated


def test_partial_failure_vault_write() -> None:
    def fake_runner(*args, **kwargs):
        return rot.subprocess.CompletedProcess(args=[], returncode=0, stdout="OK", stderr="")

    record = mk_record()
    vault = StubVault(fail_write=True)
    result = rot.process_one_server(
        record=record,
        dry_run=False,
        timeout_seconds=5,
        password_length=16,
        password_specials="!@#",
        vault_client=vault,
        racadm_runner=fake_runner,
    )
    assert result.status == "CRITICAL_PARTIAL_FAILURE"
    assert result.idrac_password_changed
    assert not result.vault_updated


def test_process_dry_run_without_vault_client() -> None:
    record = mk_record()
    result = rot.process_one_server(
        record=record,
        dry_run=True,
        timeout_seconds=5,
        password_length=16,
        password_specials="!@#",
        vault_client=None,
    )
    assert result.status == "DRY_RUN_SKIPPED"


def test_orchestrate_fail_fast_stops_after_first_failure(monkeypatch, tmp_path: Path) -> None:
    csv_path = tmp_path / "in.csv"
    csv_path.write_text(
        "idrac_host,idrac_username,current_password_vault_path,target_account_username,target_account_id,new_password_vault_path,site,environment\n"
        "h1,root,a,root,2,b,dc1,prod\n"
        "h2,root,a2,root,2,b2,dc1,prod\n",
        encoding="utf-8",
    )

    calls = {"n": 0}

    def fake_process_one_server(**kwargs):
        calls["n"] += 1
        rec = kwargs["record"]
        if calls["n"] == 1:
            return rot.make_result(rec, status="FAILED", remediation_note="x")
        return rot.make_result(rec, status="SUCCESS")

    monkeypatch.setattr(rot, "process_one_server", fake_process_one_server)

    args = SimpleNamespace(
        input_file=str(csv_path),
        dry_run=True,
        limit=None,
        concurrency=4,
        timeout=30,
        verbose=False,
        report_file=str(tmp_path / "report"),
        resume_from_report=None,
        password_length=16,
        vault_mount="secret",
        fail_fast=True,
        site_filter=None,
        environment_filter=None,
        password_specials="!@#",
        vault_password_key="password",
    )

    rc = rot.orchestrate(args)
    assert rc == 1
    assert calls["n"] == 1
