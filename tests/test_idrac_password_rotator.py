import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

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
