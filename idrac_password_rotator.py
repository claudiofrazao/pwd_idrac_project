#!/usr/bin/env python3
"""Batch Dell iDRAC password rotation with Vault as source of truth.

Workflow per host:
1) Validate input row
2) Read current password from Vault KV v2
3) Generate unique new password in memory
4) Change password with racadm
5) If racadm succeeds, write new password to Vault
6) Emit structured per-host result

Security guardrails:
- Never logs secret values
- Never uses shell=True
- Sanitizes subprocess output before persisting to report/logs
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import secrets
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import hvac
from hvac.exceptions import InvalidPath, VaultError

BASE_REQUIRED_COLUMNS: Tuple[str, ...] = (
    "idrac_host",
    "idrac_username",
    "target_account_username",
    "target_account_id",
    "new_password_vault_path",
    "site",
    "environment",
)

DEFAULT_PASSWORD_SPECIALS = "!@#$%^&*()-_=+"


@dataclass(frozen=True)
class ServerRecord:
    """CSV input row for one iDRAC endpoint."""

    idrac_host: str
    idrac_username: str
    current_password_vault_path: str
    target_account_username: str
    target_account_id: str
    new_password_vault_path: str
    site: str
    environment: str


@dataclass
class RotationResult:
    """Structured per-server result for reporting/audit."""

    idrac_host: str
    timestamp: str
    status: str
    idrac_password_changed: bool
    vault_updated: bool
    sanitized_error: str
    remediation_note: str
    site: str
    environment: str


class CsvValidationError(Exception):
    """Raised when input CSV schema or content is invalid."""


class PasswordPolicyError(Exception):
    """Raised when password policy cannot be satisfied."""


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def sanitize_text(value: str) -> str:
    """Sanitize text that may include sensitive values.

    This intentionally applies broad masking rules. It will not be perfect,
    but errs on redaction to reduce leak risk.
    """

    if not value:
        return ""
    sanitized = value
    for marker in ["password", "passwd", "pwd", "token", "secret", "VAULT_TOKEN"]:
        sanitized = sanitized.replace(marker, "[REDACTED_KEY]")
        sanitized = sanitized.replace(marker.upper(), "[REDACTED_KEY]")
    if len(sanitized) > 600:
        sanitized = sanitized[:600] + "...<truncated>"
    return sanitized


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rotate iDRAC account passwords in batch using Vault KV v2 and racadm. "
            "Vault is only updated after successful racadm change."
        )
    )
    parser.add_argument("--input-file", required=True, help="Path to CSV batch input file")
    parser.add_argument("--dry-run", action="store_true", help="Validate and simulate changes")
    parser.add_argument("--limit", type=int, default=None, help="Process only first N eligible rows")
    parser.add_argument("--concurrency", type=int, default=4, help="Thread pool size (default: 4)")
    parser.add_argument("--timeout", type=int, default=60, help="racadm timeout seconds per host")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logs (sanitized)")
    parser.add_argument("--report-file", default="rotation_report", help="Report path stem, writes .csv and .json")
    parser.add_argument(
        "--resume-from-report",
        default=None,
        help="Path to prior JSON or CSV report; previously succeeded hosts are skipped",
    )
    parser.add_argument("--password-length", type=int, default=24, help="Generated password length")
    parser.add_argument("--vault-mount", default="secret", help="Vault KV v2 mount name (default: secret)")
    parser.add_argument("--fail-fast", action="store_true", help="Stop scheduling new work after first failure")
    parser.add_argument("--site-filter", default=None, help="Only process matching site value")
    parser.add_argument("--environment-filter", default=None, help="Only process matching environment value")
    parser.add_argument("--password-specials", default=DEFAULT_PASSWORD_SPECIALS, help="Allowed special chars")
    parser.add_argument("--vault-password-key", default="password", help="Field name in Vault secret data")
    parser.add_argument(
        "--job-runner",
        choices=("local", "rundeck"),
        default="local",
        help="Execution backend for password-change jobs (default: local racadm).",
    )
    parser.add_argument("--rundeck-url", default=None, help="Rundeck base URL (required when --job-runner=rundeck).")
    parser.add_argument("--rundeck-job-id", default=None, help="Rundeck job ID (required when --job-runner=rundeck).")
    parser.add_argument(
        "--rundeck-api-token-env",
        default="RUNDECK_API_TOKEN",
        help="Environment variable name containing Rundeck API token.",
    )
    parser.add_argument(
        "--rundeck-insecure-skip-tls-verify",
        action="store_true",
        help="Disable TLS certificate verification for Rundeck API requests.",
    )
    parser.add_argument(
        "--bootstrap-shared-current-password",
        action="store_true",
        help=(
            "Bootstrap exception mode: use one shared current iDRAC password from env for all "
            "hosts, instead of reading current_password_vault_path per host from Vault."
        ),
    )
    parser.add_argument(
        "--shared-current-password-env",
        default="IDRAC_SHARED_CURRENT_PASSWORD",
        help="Environment variable name that contains shared current iDRAC password in bootstrap mode.",
    )
    return parser.parse_args(argv)


def parse_csv(path: Path, *, bootstrap_shared_current_password: bool = False) -> List[ServerRecord]:
    if not path.exists():
        raise CsvValidationError(f"Input file does not exist: {path}")

    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise CsvValidationError("CSV has no header row")
        required_columns = list(BASE_REQUIRED_COLUMNS)
        if not bootstrap_shared_current_password:
            required_columns.append("current_password_vault_path")
        missing_columns = [c for c in required_columns if c not in reader.fieldnames]
        if missing_columns:
            raise CsvValidationError(f"CSV missing required columns: {', '.join(missing_columns)}")

        records: List[ServerRecord] = []
        seen_hosts: Set[str] = set()
        for idx, row in enumerate(reader, start=2):
            normalized = {k: (row.get(k) or "").strip() for k in BASE_REQUIRED_COLUMNS}
            normalized["current_password_vault_path"] = (row.get("current_password_vault_path") or "").strip()
            missing_fields = [k for k, v in normalized.items() if not v]
            if bootstrap_shared_current_password:
                missing_fields = [k for k in missing_fields if k != "current_password_vault_path"]
            if missing_fields:
                raise CsvValidationError(
                    f"Row {idx} missing required value(s): {', '.join(missing_fields)}"
                )
            host = normalized["idrac_host"].lower()
            if host in seen_hosts:
                raise CsvValidationError(
                    f"Unsafe duplicate host '{normalized['idrac_host']}' detected at row {idx}"
                )
            seen_hosts.add(host)
            records.append(ServerRecord(**normalized))
    return records


def load_resume_success_hosts(report_path: Path) -> Set[str]:
    if not report_path.exists():
        raise FileNotFoundError(f"Resume report does not exist: {report_path}")

    successes: Set[str] = set()
    suffix = report_path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        rows = payload if isinstance(payload, list) else payload.get("results", [])
        for row in rows:
            if str(row.get("status", "")).upper() == "SUCCESS":
                host = str(row.get("idrac_host", "")).strip().lower()
                if host:
                    successes.add(host)
    elif suffix == ".csv":
        with report_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if str(row.get("status", "")).upper() == "SUCCESS":
                    host = str(row.get("idrac_host", "")).strip().lower()
                    if host:
                        successes.add(host)
    else:
        raise ValueError("resume report must be .json or .csv")
    return successes


class VaultKv2Client:
    """Minimal wrapper for Vault KV v2 operations.

    Assumes KV v2 at configurable mount point (default: secret).
    """

    def __init__(self, mount_point: str, password_key: str = "password") -> None:
        addr = os.getenv("VAULT_ADDR")
        token = os.getenv("VAULT_TOKEN")
        namespace = os.getenv("VAULT_NAMESPACE")
        if not addr:
            raise ValueError("VAULT_ADDR must be set")
        if not token:
            raise ValueError("VAULT_TOKEN must be set")

        self.mount_point = mount_point
        self.password_key = password_key
        self.client = hvac.Client(url=addr, token=token, namespace=namespace)
        if not self.client.is_authenticated():
            raise ValueError("Vault authentication failed")

    def read_password(self, path: str) -> str:
        value, _ = self.read_password_with_version(path)
        return value

    def read_password_with_version(self, path: str) -> Tuple[str, int]:
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point,
            )
        except InvalidPath as exc:
            raise ValueError(f"Vault path not found: {path}") from exc
        except VaultError as exc:
            raise ValueError(f"Vault read failed for path: {path}") from exc

        data_block = response.get("data", {})
        data = data_block.get("data", {})
        metadata = data_block.get("metadata", {})
        value = data.get(self.password_key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Vault secret missing key '{self.password_key}' at path: {path}")
        version = metadata.get("version")
        if not isinstance(version, int) or version < 1:
            raise ValueError(f"Vault metadata missing valid version at path: {path}")
        return value, version

    def _preflight_validate_secret_state(
        self,
        path: str,
        *,
        expected_current_version: Optional[int],
    ) -> None:
        """Validate current secret state before write to avoid unsafe updates."""
        try:
            metadata_response = self.client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self.mount_point,
            )
        except InvalidPath:
            if expected_current_version is not None:
                raise ValueError(
                    f"Vault pre-flight failed for path '{path}': secret no longer exists but a specific version was expected."
                )
            return
        except VaultError as exc:
            raise ValueError(f"Vault pre-flight metadata read failed for path: {path}") from exc

        metadata = metadata_response.get("data", {})
        current_version = metadata.get("current_version")
        if not isinstance(current_version, int) or current_version < 0:
            raise ValueError(f"Vault pre-flight metadata missing valid current_version at path: {path}")

        if expected_current_version is not None and current_version != expected_current_version:
            raise ValueError(
                f"Vault pre-flight version drift for path '{path}': expected version "
                f"{expected_current_version}, observed {current_version}."
            )

        if current_version < 1:
            return

        versions = metadata.get("versions", {})
        version_state = versions.get(str(current_version), {})
        if not isinstance(version_state, dict):
            return
        deletion_time = str(version_state.get("deletion_time", "") or "").strip()
        destroyed = bool(version_state.get("destroyed", False))
        if deletion_time or destroyed:
            raise ValueError(
                f"Vault pre-flight state for path '{path}' is not writable (deletion_time='{deletion_time}', destroyed={destroyed})."
            )

    def write_password(
        self,
        path: str,
        new_password: str,
        *,
        expected_current_version: Optional[int] = None,
    ) -> None:
        self._preflight_validate_secret_state(
            path,
            expected_current_version=expected_current_version,
        )
        cas: Optional[int]
        base_secret: Dict[str, object]
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point,
            )
            existing_block = response.get("data", {})
            base_secret = dict(existing_block.get("data", {}))
            metadata = existing_block.get("metadata", {})
            version = metadata.get("version")
            if not isinstance(version, int) or version < 1:
                raise ValueError(f"Vault metadata missing valid version at path: {path}")
            cas = version
        except InvalidPath:
            cas = 0
            base_secret = {}
        except VaultError as exc:
            raise ValueError(f"Vault pre-write read failed for path: {path}") from exc

        merged = dict(base_secret)
        merged[self.password_key] = new_password
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                mount_point=self.mount_point,
                secret=merged,
                cas=cas,
            )
        except VaultError as exc:
            raise ValueError(f"Vault write failed for path: {path}") from exc


class RundeckJobRunner:
    """Run enterprise password-change jobs via Rundeck."""

    def __init__(
        self,
        *,
        base_url: str,
        job_id: str,
        api_token: str,
        verify_tls: bool = True,
    ) -> None:
        if not base_url:
            raise ValueError("Rundeck base URL is required")
        if not job_id:
            raise ValueError("Rundeck job ID is required")
        if not api_token:
            raise ValueError("Rundeck API token is required")
        self.base_url = base_url.rstrip("/")
        self.job_id = job_id
        self.api_token = api_token
        self.verify_tls = verify_tls

    def _request(
        self,
        *,
        method: str,
        url: str,
        payload: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        body = None
        headers = {
            "Accept": "application/json",
            "X-Rundeck-Auth-Token": self.api_token,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url=url, method=method, data=body, headers=headers)
        context = None
        if not self.verify_tls:
            import ssl

            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, context=context, timeout=30) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"Rundeck API HTTP {exc.code}: {sanitize_text(detail)}") from exc
        except urllib.error.URLError as exc:
            raise ValueError(f"Rundeck API request failed: {sanitize_text(str(exc))}") from exc

    def run_password_change(
        self,
        *,
        record: ServerRecord,
        current_password: str,
        new_password: str,
        timeout_seconds: int,
    ) -> Tuple[bool, str]:
        run_url = f"{self.base_url}/api/41/job/{urllib.parse.quote(self.job_id, safe='')}/run"
        payload = {
            "options": {
                "idrac_host": record.idrac_host,
                "idrac_username": record.idrac_username,
                "target_account_id": record.target_account_id,
                "target_account_username": record.target_account_username,
                "current_password": current_password,
                "new_password": new_password,
            }
        }
        run_response = self._request(method="POST", url=run_url, payload=payload)
        execution = run_response.get("execution", {})
        execution_id = execution.get("id")
        if execution_id is None:
            return False, "Rundeck API did not return an execution id"

        deadline = time.monotonic() + timeout_seconds
        state_url = f"{self.base_url}/api/41/execution/{execution_id}/state"
        while time.monotonic() < deadline:
            state_payload = self._request(method="GET", url=state_url)
            exec_state = str(state_payload.get("executionState", "")).upper()
            if exec_state in {"SUCCEEDED"}:
                return True, f"Rundeck execution {execution_id} succeeded"
            if exec_state in {"FAILED", "ABORTED", "TIMEDOUT"}:
                return False, f"Rundeck execution {execution_id} ended with state={exec_state}"
            time.sleep(2)

        return False, f"Rundeck execution {execution_id} timed out after {timeout_seconds}s"


def generate_password(
    *,
    length: int,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_specials: bool = True,
    specials: str = DEFAULT_PASSWORD_SPECIALS,
) -> str:
    """Generate random password that includes at least one selected character class.

    This is designed to satisfy common iDRAC complexity expectations, but exact
    firmware policies can vary. Validate in a pilot in your environment.
    """

    classes: List[str] = []
    if use_uppercase:
        classes.append(string.ascii_uppercase)
    if use_lowercase:
        classes.append(string.ascii_lowercase)
    if use_digits:
        classes.append(string.digits)
    if use_specials:
        if not specials:
            raise PasswordPolicyError("Special characters set cannot be empty")
        classes.append(specials)

    if not classes:
        raise PasswordPolicyError("At least one character class must be enabled")
    if length < max(12, len(classes)):
        raise PasswordPolicyError(
            "Password length too short; must be >= 12 and >= enabled character classes"
        )

    rng = secrets.SystemRandom()
    chars = [rng.choice(cls) for cls in classes]
    pool = "".join(classes)
    chars.extend(rng.choice(pool) for _ in range(length - len(chars)))
    rng.shuffle(chars)
    return "".join(chars)


def run_racadm_password_change(
    *,
    record: ServerRecord,
    current_password: str,
    new_password: str,
    timeout_seconds: int,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Tuple[bool, str]:
    """Execute racadm command to update iDRAC account password.

    Default implementation uses common syntax:
      racadm -r <host> -u <idrac_username> -p <current_password>
             set iDRAC.Users.<target_account_id>.Password <new_password>

    Depending on firmware/tooling, syntax may differ. Keep all adjustments in this
    function only.
    """

    cmd = [
        "racadm",
        "-r",
        record.idrac_host,
        "-u",
        record.idrac_username,
        "-p",
        current_password,
        "set",
        f"iDRAC.Users.{record.target_account_id}.Password",
        new_password,
    ]
    try:
        completed = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"racadm timeout after {timeout_seconds}s"
    except FileNotFoundError:
        return False, "racadm binary not found in PATH"
    except OSError as exc:
        return False, sanitize_text(f"racadm execution error: {exc}")

    output = sanitize_text((completed.stdout or "") + " " + (completed.stderr or ""))
    ok_exit = completed.returncode == 0
    bad_markers = ("ERROR", "FAIL", "INVALID", "UNAUTHORIZED")
    has_bad_marker = any(marker in output.upper() for marker in bad_markers)
    success = ok_exit and not has_bad_marker
    if success:
        return True, "racadm password change reported success"
    return False, f"racadm failed rc={completed.returncode}; details={output.strip()}"


def make_result(record: ServerRecord, **kwargs: object) -> RotationResult:
    return RotationResult(
        idrac_host=record.idrac_host,
        timestamp=utc_now_iso(),
        status=str(kwargs.get("status", "FAILED")),
        idrac_password_changed=bool(kwargs.get("idrac_password_changed", False)),
        vault_updated=bool(kwargs.get("vault_updated", False)),
        sanitized_error=str(kwargs.get("sanitized_error", "")),
        remediation_note=str(kwargs.get("remediation_note", "")),
        site=record.site,
        environment=record.environment,
    )


def process_one_server(
    *,
    record: ServerRecord,
    dry_run: bool,
    timeout_seconds: int,
    password_length: int,
    password_specials: str,
    vault_client: Optional[VaultKv2Client],
    shared_current_password: Optional[str] = None,
    password_change_func: Optional[
        Callable[[ServerRecord, str, str, int], Tuple[bool, str]]
    ] = None,
    racadm_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> RotationResult:
    logging.info("Processing host=%s site=%s env=%s", record.idrac_host, record.site, record.environment)

    if dry_run:
        return make_result(
            record,
            status="DRY_RUN_SKIPPED",
            remediation_note="Dry-run mode: no iDRAC or Vault changes performed.",
        )

    if vault_client is None:
        return make_result(
            record,
            status="FAILED",
            sanitized_error="Vault client unavailable.",
            remediation_note="Initialize Vault client or use --dry-run.",
        )

    current_password = shared_current_password
    current_password_version: Optional[int] = None
    if current_password is None:
        try:
            current_password, current_password_version = vault_client.read_password_with_version(
                record.current_password_vault_path
            )
        except Exception as exc:
            return make_result(
                record,
                status="FAILED",
                sanitized_error=sanitize_text(str(exc)),
                remediation_note="Verify Vault path/auth and secret key availability.",
            )

    try:
        new_password = generate_password(length=password_length, specials=password_specials)
    except Exception as exc:
        return make_result(
            record,
            status="FAILED",
            sanitized_error=sanitize_text(str(exc)),
            remediation_note="Adjust password policy settings and retry.",
        )

    if password_change_func is None:
        racadm_ok, racadm_msg = run_racadm_password_change(
            record=record,
            current_password=current_password,
            new_password=new_password,
            timeout_seconds=timeout_seconds,
            runner=racadm_runner,
        )
    else:
        racadm_ok, racadm_msg = password_change_func(
            record,
            current_password,
            new_password,
            timeout_seconds,
        )
    if not racadm_ok:
        return make_result(
            record,
            status="FAILED",
            idrac_password_changed=False,
            vault_updated=False,
            sanitized_error=sanitize_text(racadm_msg),
            remediation_note="Investigate iDRAC reachability/credentials and rerun.",
        )

    try:
        expected_version = (
            current_password_version
            if record.new_password_vault_path == record.current_password_vault_path
            else None
        )
        vault_client.write_password(
            record.new_password_vault_path,
            new_password,
            expected_current_version=expected_version,
        )
    except Exception as exc:
        return make_result(
            record,
            status="CRITICAL_PARTIAL_FAILURE",
            idrac_password_changed=True,
            vault_updated=False,
            sanitized_error=sanitize_text(str(exc)),
            remediation_note=(
                "iDRAC password changed but Vault was not updated. Perform urgent manual "
                "Vault remediation with controlled break-glass process."
            ),
        )

    return make_result(
        record,
        status="SUCCESS",
        idrac_password_changed=True,
        vault_updated=True,
        sanitized_error="",
        remediation_note="",
    )


def filter_records(
    records: Iterable[ServerRecord],
    *,
    site_filter: Optional[str],
    environment_filter: Optional[str],
    resume_success_hosts: Set[str],
    limit: Optional[int],
) -> Tuple[List[ServerRecord], int]:
    skipped = 0
    selected: List[ServerRecord] = []
    for rec in records:
        if site_filter and rec.site != site_filter:
            skipped += 1
            continue
        if environment_filter and rec.environment != environment_filter:
            skipped += 1
            continue
        if rec.idrac_host.lower() in resume_success_hosts:
            skipped += 1
            continue
        selected.append(rec)
        if limit is not None and len(selected) >= limit:
            break
    return selected, skipped


def summarize(results: Sequence[RotationResult], initial_skipped: int = 0) -> Dict[str, int]:
    summary = {
        "total": len(results) + initial_skipped,
        "succeeded": 0,
        "failed": 0,
        "partial_failures": 0,
        "skipped": initial_skipped,
    }
    for result in results:
        if result.status == "SUCCESS":
            summary["succeeded"] += 1
        elif result.status == "CRITICAL_PARTIAL_FAILURE":
            summary["partial_failures"] += 1
        elif result.status.startswith("DRY_RUN"):
            summary["skipped"] += 1
        else:
            summary["failed"] += 1
    return summary


def write_reports(results: Sequence[RotationResult], report_stem: str, summary: Dict[str, int]) -> None:
    json_path = Path(f"{report_stem}.json")
    csv_path = Path(f"{report_stem}.csv")

    payload = {
        "generated_at": utc_now_iso(),
        "summary": summary,
        "results": [asdict(r) for r in results],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()) if results else [
            "idrac_host",
            "timestamp",
            "status",
            "idrac_password_changed",
            "vault_updated",
            "sanitized_error",
            "remediation_note",
            "site",
            "environment",
        ])
        writer.writeheader()
        for row in results:
            writer.writerow(asdict(row))


def orchestrate(args: argparse.Namespace) -> int:
    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")
    if args.timeout < 1:
        raise ValueError("--timeout must be >= 1")

    bootstrap_mode = bool(getattr(args, "bootstrap_shared_current_password", False))
    shared_password_env_name = str(
        getattr(args, "shared_current_password_env", "IDRAC_SHARED_CURRENT_PASSWORD")
    )
    records = parse_csv(
        Path(args.input_file),
        bootstrap_shared_current_password=bootstrap_mode,
    )

    shared_current_password: Optional[str] = None
    if bootstrap_mode:
        env_name = shared_password_env_name
        shared_current_password = os.getenv(env_name)
        if not shared_current_password:
            raise ValueError(
                f"Bootstrap mode requires environment variable '{env_name}' to be set with the shared current password."
            )

    resume_success: Set[str] = set()
    if args.resume_from_report:
        resume_success = load_resume_success_hosts(Path(args.resume_from_report))

    selected, initially_skipped = filter_records(
        records,
        site_filter=args.site_filter,
        environment_filter=args.environment_filter,
        resume_success_hosts=resume_success,
        limit=args.limit,
    )
    logging.info(
        "Loaded=%s selected=%s initially_skipped=%s dry_run=%s",
        len(records),
        len(selected),
        initially_skipped,
        args.dry_run,
    )

    if not selected:
        logging.warning("No eligible rows selected after filters/resume/limit")
        summary = {
            "total": len(records),
            "succeeded": 0,
            "failed": 0,
            "partial_failures": 0,
            "skipped": len(records),
        }
        write_reports([], args.report_file, summary)
        return 0

    vault_client: Optional[VaultKv2Client] = None
    if not args.dry_run:
        vault_client = VaultKv2Client(mount_point=args.vault_mount, password_key=args.vault_password_key)

    password_change_func: Optional[Callable[[ServerRecord, str, str, int], Tuple[bool, str]]] = None
    if getattr(args, "job_runner", "local") == "rundeck":
        token_env = getattr(args, "rundeck_api_token_env", "RUNDECK_API_TOKEN")
        token_value = os.getenv(token_env)
        if not token_value:
            raise ValueError(
                f"--job-runner=rundeck requires environment variable '{token_env}' with API token."
            )
        rundeck_runner = RundeckJobRunner(
            base_url=getattr(args, "rundeck_url", None) or "",
            job_id=getattr(args, "rundeck_job_id", None) or "",
            api_token=token_value,
            verify_tls=not bool(getattr(args, "rundeck_insecure_skip_tls_verify", False)),
        )

        def _rundeck_change(record: ServerRecord, current_password: str, new_password: str, timeout_seconds: int) -> Tuple[bool, str]:
            return rundeck_runner.run_password_change(
                record=record,
                current_password=current_password,
                new_password=new_password,
                timeout_seconds=timeout_seconds,
            )

        password_change_func = _rundeck_change

    results: List[RotationResult] = []
    lock = Lock()
    if args.fail_fast:
        for record in selected:
            result = process_one_server(
                record=record,
                dry_run=args.dry_run,
                timeout_seconds=args.timeout,
                password_length=args.password_length,
                password_specials=args.password_specials,
                vault_client=vault_client,
                shared_current_password=shared_current_password,
                password_change_func=password_change_func,
            )
            results.append(result)
            if result.status in {"FAILED", "CRITICAL_PARTIAL_FAILURE"}:
                level = logging.CRITICAL if result.status == "CRITICAL_PARTIAL_FAILURE" else logging.ERROR
                logging.log(level, "Host=%s status=%s (fail-fast stopping)", result.idrac_host, result.status)
                break
            logging.info("Host=%s status=%s", result.idrac_host, result.status)
    else:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_record = {}
            for record in selected:
                future = executor.submit(
                    process_one_server,
                    record=record,
                    dry_run=args.dry_run,
                    timeout_seconds=args.timeout,
                    password_length=args.password_length,
                        password_specials=args.password_specials,
                        vault_client=vault_client,
                        shared_current_password=shared_current_password,
                        password_change_func=password_change_func,
                    )
                future_to_record[future] = record

            for future in as_completed(future_to_record):
                record = future_to_record[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = make_result(
                        record,
                        status="FAILED",
                        sanitized_error=sanitize_text(f"Unhandled worker exception: {exc}"),
                        remediation_note="Inspect worker logs and retry host.",
                    )

                with lock:
                    results.append(result)

                if result.status in {"FAILED", "CRITICAL_PARTIAL_FAILURE"}:
                    level = logging.CRITICAL if result.status == "CRITICAL_PARTIAL_FAILURE" else logging.ERROR
                    logging.log(level, "Host=%s status=%s", result.idrac_host, result.status)
                else:
                    logging.info("Host=%s status=%s", result.idrac_host, result.status)

    results.sort(key=lambda r: r.idrac_host)
    summary = summarize(results, initial_skipped=initially_skipped)
    write_reports(results, args.report_file, summary)

    logging.info("Summary: %s", json.dumps(summary))
    return 2 if summary["partial_failures"] else (1 if summary["failed"] else 0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)
    try:
        return orchestrate(args)
    except CsvValidationError as exc:
        logging.error("CSV validation error: %s", sanitize_text(str(exc)))
        return 1
    except Exception as exc:
        logging.critical("Fatal error: %s", sanitize_text(str(exc)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
