# Dell iDRAC Batch Password Rotator

## Overview

This project provides a production-oriented Python CLI to rotate Dell iDRAC account passwords in batch across many servers.

It exists to solve a common operational risk in infrastructure teams: credential drift between hardware management interfaces (iDRAC) and centralized secret stores. In this workflow, HashiCorp Vault is the source of truth for credential retrieval and persistence, while `racadm` is the control-plane utility used to apply password changes on each iDRAC endpoint.

The tool is intentionally designed so Vault is updated **only after** a successful password change on the target iDRAC. This ordering minimizes drift and makes partial-failure scenarios explicit, detectable, and actionable.

## Key Features

- Batch password rotation from CSV input.
- Unique, random password generation per server.
- HashiCorp Vault KV v2 integration for read/write secret workflows.
- Dell `racadm` integration for iDRAC password updates.
- `--dry-run` mode for safe validation without iDRAC or Vault writes.
- Simulation-friendly architecture via mocked Vault and racadm runners in tests.
- Concurrency control with configurable thread pool (`--concurrency`).
- Structured reporting to both CSV and JSON.
- Resume support (`--resume-from-report`) to skip prior successful hosts.
- Explicit partial-failure detection (`CRITICAL_PARTIAL_FAILURE`) when iDRAC changes but Vault update fails.
- Sanitized, audit-friendly logging that avoids secret disclosure.

## Architecture Summary

Main components:

- **CLI/config (`argparse`)**: Parses runtime flags (input file, filters, concurrency, timeout, dry-run, reporting, resume behavior).
- **CSV loader/validator**: Enforces required columns, non-empty fields, and duplicate-host prevention.
- **Vault client (`VaultKv2Client`)**: Reads and writes password fields from/to KV v2 paths with CAS-safe updates.
- **Password policy engine (`generate_password`)**: Produces strong random passwords with configurable length and special-character set.
- **racadm client (`run_racadm_password_change`)**: Executes password update command and classifies outcomes using exit code and output markers.
- **Orchestrator (`orchestrate`)**: Applies filters, resume behavior, concurrency/fail-fast execution, summary generation, and exit code logic.
- **Reporting (`write_reports`)**: Emits per-host result rows and aggregate summary in JSON and CSV.
- **Simulation backends**: Test-time stubs/mocks for Vault and racadm to simulate success, failure, and partial failure safely.

Per-server workflow (high level):

1. Validate server row from CSV.
2. Read current password from Vault.
3. Generate a new password in memory.
4. Execute `racadm` password change.
5. If `racadm` succeeds, write new password to Vault.
6. Record structured status for reporting and audit.

## Safe Workflow

The intended safe sequence is:

1. **Read current password from Vault** (`current_password_vault_path`).
2. **Generate new password in memory** (never persisted in plaintext logs).
3. **Apply password change with `racadm`** on target iDRAC.
4. **Only after success, update Vault** (`new_password_vault_path`).
5. **If Vault update fails after iDRAC success, mark `CRITICAL_PARTIAL_FAILURE`** and trigger urgent remediation.

This sequence is the core control that reduces drift while still surfacing high-risk split-brain conditions.

## Project Structure

```text
.
├── idrac_password_rotator.py        # Main CLI, orchestration, Vault/racadm integration, reporting
├── requirements.txt                 # Python dependencies
├── sample_idrac_batch.csv           # Example input dataset
├── tests/
│   └── test_idrac_password_rotator.py  # Unit tests (CSV validation, flow outcomes, fail-fast)
└── README.md                        # This documentation
```

## Requirements

- **Python**: 3.9+ recommended.
- **racadm**: `racadm` binary installed and available in `PATH` on the execution host.
- **Vault access**:
  - Network reachability to Vault.
  - Valid token with read/write access to relevant KV v2 paths.
- **Operating system**: Linux automation host is assumed (or equivalent environment where Python and `racadm` are available).

## Installation

```bash
git clone <REPO_URL>
cd pwd_idrac_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify `racadm` availability before running production rotations:

```bash
racadm --version
which racadm
```

If `racadm` is not found, install Dell OpenManage / RACADM tooling per your platform standard.

## Configuration

Set Vault connectivity/authentication through environment variables:

```bash
export VAULT_ADDR="https://vault.example.internal:8200"
export VAULT_TOKEN="<short-lived-rotation-token>"
# Optional (required only in namespaced Vault deployments)
export VAULT_NAMESPACE="infrastructure/operations"
```

### Variable Reference

- `VAULT_ADDR` (required): Vault API endpoint.
- `VAULT_TOKEN` (required): Token used by the tool for KV v2 read/write.
- `VAULT_NAMESPACE` (optional): Vault namespace, if your deployment uses enterprise namespaces.

### Related CLI options (configuration at runtime)

- `--vault-mount` (default: `secret`) for KV v2 mount name.
- `--vault-password-key` (default: `password`) for secret field name.
- `--password-length` and `--password-specials` for password policy tuning.
- `--timeout` for per-host `racadm` timeout.

## Input CSV Format

Required header columns:

- `idrac_host`
- `idrac_username`
- `current_password_vault_path`
- `target_account_username`
- `target_account_id`
- `new_password_vault_path`
- `site`
- `environment`

### Sample CSV

```csv
idrac_host,idrac_username,current_password_vault_path,target_account_username,target_account_id,new_password_vault_path,site,environment
10.20.1.15,root,idrac/prod/site-a/r740-01/current,root,2,idrac/prod/site-a/r740-01/current,dc-a,prod
10.20.1.16,root,idrac/prod/site-a/r740-02/current,root,2,idrac/prod/site-a/r740-02/current,dc-a,prod
10.30.4.10,root,idrac/stage/site-b/r650-01/current,root,2,idrac/stage/site-b/r650-01/current,dc-b,stage
```

### Field Meaning

- `idrac_host`: iDRAC endpoint hostname or IP.
- `idrac_username`: Administrative iDRAC login used for racadm session.
- `current_password_vault_path`: Vault KV path to read current password from.
- `target_account_username`: Intended iDRAC account username being rotated (metadata/traceability).
- `target_account_id`: iDRAC user slot/account ID used in racadm command (`iDRAC.Users.<ID>.Password`).
- `new_password_vault_path`: Vault KV path to write new password to (often same as current path).
- `site`: Site tag for filtering and reporting.
- `environment`: Environment tag (`prod`, `stage`, etc.) for filtering and reporting.

## CLI Usage

Basic help:

```bash
python idrac_password_rotator.py --help
```

### 1) Dry-run validation (no iDRAC/Vault updates)

```bash
python idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --dry-run \
  --report-file reports/dryrun_2026-03-25
```

### 2) Pilot execution with limit

```bash
python idrac_password_rotator.py \
  --input-file batch_prod.csv \
  --limit 5 \
  --concurrency 2 \
  --timeout 90 \
  --report-file reports/pilot5
```

### 3) Production run

```bash
python idrac_password_rotator.py \
  --input-file batch_prod.csv \
  --concurrency 6 \
  --timeout 90 \
  --vault-mount secret \
  --vault-password-key password \
  --report-file reports/prod_full
```

### 4) Filtered run by site/environment

```bash
python idrac_password_rotator.py \
  --input-file batch_all_sites.csv \
  --site-filter dc-a \
  --environment-filter prod \
  --report-file reports/dc-a_prod
```

### 5) Simulation run (safe pre-production verification)

```bash
# Operational simulation using dry-run
python idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --dry-run \
  --limit 20 \
  --report-file reports/sim_dryrun
```

### 6) Resume from previous report

```bash
python idrac_password_rotator.py \
  --input-file batch_prod.csv \
  --resume-from-report reports/prod_full.json \
  --report-file reports/prod_resume
```

The resume feature skips hosts already marked `SUCCESS` in prior JSON/CSV report.

## Simulation Mode

This project supports two practical simulation approaches:

1. **CLI dry-run simulation (`--dry-run`)**
   - Validates CSV loading, filtering, reporting, and orchestration behavior.
   - Does **not** contact Vault.
   - Does **not** execute `racadm` changes.

2. **Test harness simulation (pytest with stubs/mocks)**
   - Replaces Vault and `racadm` calls with controlled fake backends.
   - Supports deterministic failure injection (e.g., racadm failure, Vault write failure after racadm success).
   - Validates status outcomes and remediation signaling.

Example simulation checks:

```bash
pytest -q
pytest -k "partial_failure or racadm_failure" -q
```

## Reports and Output

Each run writes:

- `<report-file>.json`
- `<report-file>.csv`

### JSON report structure

Top-level keys:

- `generated_at`
- `summary`
- `results` (array of per-host result objects)

### Important per-host fields

- `idrac_host`: target endpoint.
- `timestamp`: UTC processing time.
- `status`: terminal status (`SUCCESS`, `FAILED`, etc.).
- `idrac_password_changed`: whether racadm password update succeeded.
- `vault_updated`: whether Vault write succeeded.
- `sanitized_error`: masked error details safe for logs/review.
- `remediation_note`: operator guidance for corrective action.
- `site`, `environment`: context tags from CSV.

### Stdout/log summary

At end of run, summary includes counts:

- `total`
- `succeeded`
- `failed`
- `partial_failures`
- `skipped`

Exit codes:

- `0`: no failures.
- `1`: one or more failures.
- `2`: one or more critical partial failures.

## Status Values

Current status values used by implementation:

- `SUCCESS`
  - iDRAC password changed and Vault updated successfully.
- `FAILED`
  - Rotation failed before full completion (Vault read issue, password policy issue, racadm failure, timeout, etc.).
- `CRITICAL_PARTIAL_FAILURE`
  - iDRAC password changed, but Vault update failed. Immediate remediation required.
- `DRY_RUN_SKIPPED`
  - Dry-run mode; host validated in workflow but no state-changing operations executed.

## Failure Handling and Recovery

### Vault read failure

- **Symptom**: `FAILED` with Vault read/auth/path message.
- **Action**:
  - Validate token permissions and TTL.
  - Validate KV mount/path and key (`--vault-password-key`).
  - Re-run for affected scope.

### racadm failure

- **Symptom**: `FAILED`, `idrac_password_changed=false`, `vault_updated=false`.
- **Action**:
  - Check DNS/network reachability to iDRAC.
  - Validate current credentials and account ID.
  - Reproduce command manually in maintenance context.

### Timeout

- **Symptom**: `FAILED` with timeout text.
- **Action**:
  - Increase `--timeout` for slow networks/firmware.
  - Reduce `--concurrency` to avoid saturation.
  - Retry subset.

### Vault write failure after successful racadm change

- **Symptom**: `CRITICAL_PARTIAL_FAILURE`, `idrac_password_changed=true`, `vault_updated=false`.
- **Action (urgent)**:
  1. Open incident/change exception immediately.
  2. Confirm new iDRAC credential via controlled access.
  3. Update Vault path with verified credential under break-glass procedure.
  4. Record remediation evidence and close incident.

### Resume behavior

- Use `--resume-from-report` with prior JSON/CSV report to skip hosts that already reached `SUCCESS`.
- Partial failures and failures remain eligible for retry after remediation.

## Testing

Run test suite:

```bash
pytest -q
```

What is covered:

- CSV validation (including duplicate host rejection).
- Password generation policy baseline checks.
- Successful end-to-end per-host flow with mocked dependencies.
- racadm failure handling.
- Critical partial failure handling when Vault write fails post-racadm.
- Dry-run per-host behavior.
- Fail-fast orchestration behavior.

Mocking strategy:

- Vault operations are replaced with in-memory stub classes.
- `racadm` execution is replaced with fake subprocess runner responses.
- No real Vault or iDRAC calls are needed for unit tests.

Safe validation before production:

1. Run unit tests.
2. Run CLI with `--dry-run` on real CSV.
3. Execute pilot on small host set with live dependencies.

## Pilot Rollout Guidance

Recommended rollout sequence:

1. **Dry-run first** on full intended CSV to validate schema/filter/report behavior.
2. **Simulation tests** (`pytest`) to validate expected failure handling paths.
3. **Pilot with 5 servers** (`--limit 5`, low concurrency).
4. **Expand to ~20 servers** after successful pilot and report review.
5. **Proceed to full batch** during approved maintenance/change window.

Why this matters:

- Reduces blast radius.
- Validates environment-specific iDRAC/Vault behavior before full rollout.
- Ensures team readiness for partial-failure remediation.

## Security Considerations

- Secret values are never intentionally logged; output is sanitized before persistence.
- Do not hardcode credentials in code, CSV, or shell history.
- Use least-privilege Vault token scoped only to required KV paths and operations.
- Prefer short-lived Vault tokens and controlled execution context.
- Protect report artifacts (`*.json`, `*.csv`) because they contain host inventory and operational metadata.
- Validate exact `racadm` command syntax in a lab environment before production.
- Confirm generated password policy aligns with active Dell iDRAC firmware complexity rules.
- Restrict who can run this tool and access result artifacts.

## Known Assumptions and Environment-Specific Validation

Before production, validate these assumptions explicitly:

1. **racadm syntax compatibility**
   - Command format for your firmware/tooling matches implementation (`set iDRAC.Users.<ID>.Password ...`).
2. **Vault KV v2 semantics**
   - Target mount is KV v2 and supports CAS behavior as expected.
3. **iDRAC account ID behavior**
   - `target_account_id` maps correctly to intended user slot across hardware generations.
4. **Password policy compatibility**
   - Generated length/special character set are accepted by all target iDRAC versions.
5. **Network and timeout envelope**
   - Execution host can reach all iDRAC endpoints and Vault with acceptable latency.
6. **Concurrency tolerance**
   - `--concurrency` does not overwhelm network devices, iDRAC interfaces, or Vault rate limits.

## Troubleshooting

- **`CSV validation error` at startup**
  - Check header names and required non-empty fields.
  - Ensure no duplicate `idrac_host` values.

- **`Vault authentication failed`**
  - Validate `VAULT_ADDR`, `VAULT_TOKEN`, and optional `VAULT_NAMESPACE`.
  - Confirm token policy and namespace scope.

- **`racadm binary not found in PATH`**
  - Install/enable RACADM tooling and verify with `which racadm`.

- **Frequent racadm timeouts/failures**
  - Lower concurrency, increase timeout, and verify network ACL/firewall paths.

- **Unexpected partial failures**
  - Investigate Vault availability/permissions during writes.
  - Follow critical remediation workflow before retries.

## Future Improvements

Potential enhancements for enterprise adoption:

- Vault AppRole/JWT/OIDC auth support (reducing static token usage).
- Pre-flight validation for Vault secret version/state before write.
- Native scheduling hooks for approved change windows.
- Metrics export (Prometheus/OpenTelemetry) for run observability.
- Integration with enterprise job runners (e.g., Rundeck/AWX/Jenkins).
- Optional encrypted-at-rest report outputs.
