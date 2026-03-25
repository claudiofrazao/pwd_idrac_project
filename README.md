# iDRAC Password Rotator (Vault + racadm/Rundeck)

## What this tool does

`idrac_password_rotator.py` is a batch CLI that rotates iDRAC account passwords from a CSV inventory.

For each selected host, the implemented workflow is:

1. Obtain the current password (from Vault in normal mode, or from a shared env var in bootstrap mode).
2. Generate a new random password in memory.
3. Attempt the password change on iDRAC (local `racadm` or Rundeck job runner).
4. Only if step 3 succeeds, write the new password to Vault KV v2.
5. Emit per-host result rows and run summary to JSON/CSV reports.

The code explicitly models the split-brain condition where iDRAC change succeeds but Vault write fails as `CRITICAL_PARTIAL_FAILURE`.

---

## Current scope and non-goals

### In scope (implemented)

- CSV-driven batch execution with schema validation.
- Host filtering (`site`, `environment`), `--limit`, and resume from prior report successes.
- Per-host status reporting and aggregate summary.
- Concurrency via thread pool, plus optional fail-fast sequential mode.
- Vault KV v2 read/write with pre-flight metadata checks and CAS write behavior.
- Bootstrap exception mode using one shared current password env var.
- Optional Rundeck job runner backend for the password-change step.

### Non-goals / not implemented

- No device discovery; targets must come from CSV.
- No encrypted local state database/checkpoint file (resume is report-driven only).
- No automatic rollback if Vault update fails after iDRAC change.
- No built-in scheduler; execution cadence is external (cron/Rundeck/etc.).
- No guarantee that `racadm` command syntax works across all firmware revisions (must be validated in your environment).

---

## How it works

### Per-host lifecycle (`process_one_server`)

- If `--dry-run`, host is marked `DRY_RUN_SKIPPED`; no iDRAC/Vault change is attempted.
- Otherwise:
  - Read current password (+ version) from Vault unless bootstrap shared password is active.
  - Generate a new password (`generate_password`) with required character classes and minimum length logic.
  - Execute password change via:
    - `run_racadm_password_change` (local), or
    - Rundeck API execution wrapper (`RundeckJobRunner`) when `--job-runner rundeck`.
  - If change failed: host status `FAILED`, Vault not updated.
  - If change succeeded: write to Vault with pre-flight validation and CAS semantics.
  - If Vault write then fails: host status `CRITICAL_PARTIAL_FAILURE` with remediation note.
  - If both succeed: host status `SUCCESS`.

### Exit codes

The process returns:

- `0`: no host failures/partial failures.
- `1`: one or more `FAILED` hosts (or fatal/validation error).
- `2`: one or more `CRITICAL_PARTIAL_FAILURE` hosts.

---

## Execution modes

## 1) Normal mode (default)

- Current password is read per host from `current_password_vault_path`.
- New password is written to `new_password_vault_path` after successful change.
- If read path equals write path, Vault pre-flight enforces expected version matching.

## 2) Bootstrap mode

Enabled by `--bootstrap-shared-current-password`.

- Current password is **not** read from Vault per host.
- Current password comes from env var `IDRAC_SHARED_CURRENT_PASSWORD` (or custom via `--shared-current-password-env`).
- CSV can omit `current_password_vault_path` header/value in this mode.
- If env var is missing, orchestration fails before processing.

Use case appears to be first-time rollout where fleet still shares one known current password.

## 3) Simulation / dry-run mode

Enabled by `--dry-run`.

- CSV parsing/filtering/resume selection still runs.
- Vault client is not initialized.
- iDRAC change and Vault write are skipped.
- Reports are still produced with `DRY_RUN_SKIPPED` rows and skipped counts.

---

## Architecture and code structure

```text
.
├── idrac_password_rotator.py
├── tests/
│   └── test_idrac_password_rotator.py
├── sample_idrac_batch.csv
├── requirements.txt
└── README.md
```

### Main components

- `parse_args`: CLI surface.
- `parse_csv`: schema/content/duplicate-host validation.
- `VaultKv2Client`: Vault auth + KV v2 read/write + pre-flight metadata validation.
- `run_racadm_password_change`: local `racadm` command execution.
- `RundeckJobRunner`: Rundeck API integration for per-host password-change job execution.
- `process_one_server`: per-host state machine and status mapping.
- `orchestrate`: selection, concurrency/fail-fast scheduling, reporting, exit code.
- `write_reports`: JSON and CSV artifact generation.

---

## Requirements and external dependencies

- Python 3.x (repository does not pin interpreter version explicitly).
- Python package: `hvac` (`requirements.txt`).
- Vault KV v2 endpoint reachable from runtime.
- Vault token with required read/write/metadata permissions.
- Local mode only: `racadm` binary available in `PATH` and compatible with target iDRAC.
- Rundeck mode only:
  - Rundeck URL and job ID.
  - API token in environment variable (default `RUNDECK_API_TOKEN`).

---

## Configuration

### Environment variables

Vault:

- `VAULT_ADDR` (required unless dry-run): Vault base URL.
- `VAULT_TOKEN` (required unless dry-run): Vault token.
- `VAULT_NAMESPACE` (optional): passed to `hvac.Client`.

Bootstrap mode:

- `IDRAC_SHARED_CURRENT_PASSWORD` by default, or custom env name via `--shared-current-password-env`.

Rundeck mode:

- `RUNDECK_API_TOKEN` by default, or custom env name via `--rundeck-api-token-env`.

### CLI options (implemented)

```bash
python3 idrac_password_rotator.py --input-file <csv> [options]
```

Important options:

- `--dry-run`
- `--limit <N>`
- `--concurrency <N>` (default `4`)
- `--timeout <seconds>` (default `60`)
- `--report-file <stem>` (default `rotation_report`)
- `--resume-from-report <path.{json|csv}>`
- `--password-length <N>` (default `24`, must satisfy policy checks)
- `--password-specials <chars>`
- `--vault-mount <mount>` (default `secret`)
- `--vault-password-key <key>` (default `password`)
- `--site-filter <site>`
- `--environment-filter <env>`
- `--fail-fast`
- `--job-runner local|rundeck` (default `local`)
- `--rundeck-url <url>`
- `--rundeck-job-id <id>`
- `--rundeck-api-token-env <ENV_NAME>`
- `--rundeck-insecure-skip-tls-verify`
- `--bootstrap-shared-current-password`
- `--shared-current-password-env <ENV_NAME>`

---

## Input format

Expected CSV headers in normal mode:

- `idrac_host`
- `idrac_username`
- `current_password_vault_path`
- `target_account_username`
- `target_account_id`
- `new_password_vault_path`
- `site`
- `environment`

Bootstrap mode allows `current_password_vault_path` column to be omitted.

Validation behavior:

- Missing header(s) => validation error.
- Empty required value(s) => validation error with row number.
- Duplicate host (case-insensitive) => validation error.

See `sample_idrac_batch.csv` for an example dataset format.

---

## CLI usage

### Basic run (local racadm)

```bash
export VAULT_ADDR="https://vault.example"
export VAULT_TOKEN="..."
python3 idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --report-file reports/rotation_run
```

### Dry run

```bash
python3 idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --dry-run \
  --report-file reports/dry_run
```

### Bootstrap mode

```bash
export VAULT_ADDR="https://vault.example"
export VAULT_TOKEN="..."
export IDRAC_SHARED_CURRENT_PASSWORD="current-shared-password"
python3 idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --bootstrap-shared-current-password \
  --report-file reports/bootstrap_run
```

### Rundeck backend mode

```bash
export VAULT_ADDR="https://vault.example"
export VAULT_TOKEN="..."
export RUNDECK_API_TOKEN="..."
python3 idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --job-runner rundeck \
  --rundeck-url https://rundeck.example.org \
  --rundeck-job-id <job-id> \
  --report-file reports/rundeck_run
```

---

## Reports and statuses

The tool writes two files using `--report-file <stem>`:

- `<stem>.json`
- `<stem>.csv`

### JSON format

Contains:

- `generated_at`
- `summary`:
  - `total`
  - `succeeded`
  - `failed`
  - `partial_failures`
  - `skipped`
- `results`: array of per-host result objects.

### Per-host status values used by code

- `SUCCESS`
- `FAILED`
- `CRITICAL_PARTIAL_FAILURE`
- `DRY_RUN_SKIPPED`

Resume behavior (`--resume-from-report`) only skips hosts with status `SUCCESS` in the prior report.

---

## Vault behavior

### Read path behavior

Normal mode reads current password from `current_password_vault_path`, requiring:

- secret exists,
- configured password key exists and is non-empty string,
- metadata version is present and valid.

### Pre-flight validation before write

Before writing to `new_password_vault_path`, code checks Vault metadata state:

- metadata can be read (or path missing under allowed conditions),
- `current_version` is valid,
- if expected version is provided, it matches current version,
- latest version is not deleted/destroyed.

Expected version is currently enforced only for in-place rotations (`new_password_vault_path == current_password_vault_path`).

### Write behavior

- Reads existing secret data if present.
- Merges existing data with new password field.
- Uses KV v2 `create_or_update_secret` with `cas`:
  - `cas=version` for existing secret,
  - `cas=0` when path is absent.

---

## racadm behavior and environment-specific assumptions

Local backend command shape is:

```bash
racadm -r <idrac_host> -u <idrac_username> -p <current_password> \
  set iDRAC.Users.<target_account_id>.Password <new_password>
```

Result evaluation in current code:

- success requires `returncode == 0`, and
- combined stdout/stderr must not contain markers: `ERROR`, `FAIL`, `INVALID`, `UNAUTHORIZED`.

Important assumptions to validate in target environment:

- `racadm` command syntax may vary by firmware/tooling version.
- Account ID mapping (`target_account_id`) must match iDRAC local user model.
- Network reachability and TLS behavior for iDRAC endpoints are external dependencies.

---

## Pre-flight validation behavior

Pre-flight validation is implemented in Vault write path and is not a separate global stage.

What it does:

- validates target secret metadata and writable state immediately before update,
- detects version drift when in-place rotation expects a specific version,
- blocks writes when latest version state is deleted/destroyed.

What it does not appear to do:

- does not correlate versions across different read/write paths,
- does not perform a standalone “validate all hosts then execute” two-phase workflow.

---

## Rundeck execution model

With `--job-runner rundeck`, the tool:

1. Calls Rundeck `POST /api/41/job/<job_id>/run` with per-host options:
   `idrac_host`, `idrac_username`, `target_account_id`, `target_account_username`, `current_password`, `new_password`.
2. Polls `GET /api/41/execution/<execution_id>/state` every ~2 seconds.
3. Treats `SUCCEEDED` as success and `FAILED|ABORTED|TIMEDOUT` as failure.
4. On success, continues with Vault write in this CLI.

Notes:

- This CLI still owns Vault read/write and reporting.
- `--rundeck-insecure-skip-tls-verify` disables TLS verification for Rundeck API calls.

---

## Failure handling and recovery

### Failure classes

- `FAILED`: iDRAC change failed, Vault unchanged.
- `CRITICAL_PARTIAL_FAILURE`: iDRAC changed but Vault update failed.

### Recovery mechanisms implemented

- Resume only skips previous `SUCCESS` hosts.
- `--fail-fast` stops after first failed/partial-failure host (sequential mode).
- Non-fail-fast mode processes all selected hosts and reports all outcomes.

### Operational implication

`CRITICAL_PARTIAL_FAILURE` indicates credential drift and requires urgent manual remediation of Vault state and access processes.

---

## Testing

Repository includes unit tests in `tests/test_idrac_password_rotator.py` that cover:

- CSV validation behavior.
- Password policy generation basics.
- Successful and failed per-host flows.
- Partial failure semantics.
- Bootstrap-specific behavior.
- Fail-fast behavior.
- Rundeck token requirement check.

Tests use stubs/mocks for Vault and command runners; they do not perform real racadm/Vault/Rundeck integration.

Run:

```bash
pytest -q
```

---

## Security considerations before making this repository public

This repository is close to publishable, but review these items first.

1. **Sample data hygiene**
   - `sample_idrac_batch.csv` contains private-style naming patterns and network-like addressing.
   - Confirm all sample hosts, Vault paths, sites, and environments are synthetic and acceptable for public exposure.

2. **Vault path conventions**
   - Sample/test paths reveal naming structure (`idrac/<env>/<site>/<host>/current`).
   - Decide whether to keep, generalize, or redact these conventions.

3. **Report artifact handling**
   - Generated reports include host identifiers, site/environment tags, and sanitized error text.
   - Ensure no real production reports are committed; keep `.gitignore` and CI artifact policies strict.

4. **Rundeck integration metadata**
   - Confirm no real Rundeck URLs/job IDs/tokens appear in docs, examples, CI, or scripts.

5. **Fixtures and tests**
   - Test fixtures currently appear synthetic; re-check periodically before publishing snapshots.

6. **Secret handling expectations**
   - Tool avoids logging cleartext secrets, but still transmits passwords to racadm/Rundeck backends.
   - Validate runtime logging, job option redaction, and process visibility controls in your environment.

---

## Public-repository readiness checklist

Before publishing, explicitly review:

- `sample_idrac_batch.csv` for real hostnames/IPs or internal taxonomy leakage.
- Any committed `*.json` / `*.csv` reports from previous runs (should not exist).
- README examples for internal URLs, Vault mount/path conventions, or environment names.
- CI/CD configs (if later added) for hardcoded Vault/Rundeck references.
- Issue templates/wiki/docs for screenshots or run logs containing host IDs.

The current implementation appears to be intentionally careful about secrets in logs, but operational metadata still needs governance.

---

## Limitations and assumptions

- The current implementation assumes Vault KV v2 semantics and `hvac` compatibility.
- The current implementation assumes a working `racadm` CLI with the coded command format.
- Concurrency shares a single Vault client across worker threads; validate this under production load.
- Sanitization is broad string replacement and truncation; it reduces but does not formally guarantee zero secret leakage.
- Rundeck API version path is hardcoded to `/api/41`; validate against your Rundeck version.
- `target_account_username` is carried through CSV/options payload but local racadm path currently uses account ID for password set command.

---

## Troubleshooting

- **`VAULT_ADDR must be set` / `VAULT_TOKEN must be set`**:
  - Set required env vars for non-dry-run execution.

- **`Vault authentication failed`**:
  - Validate token, namespace, and network path to Vault.

- **`Vault path not found` / missing password key**:
  - Verify input path and `--vault-password-key` match actual secret schema.

- **`racadm binary not found in PATH`**:
  - Install racadm/OpenManage tooling on execution host.

- **Hosts marked `CRITICAL_PARTIAL_FAILURE`**:
  - Treat as urgent drift; reconcile Vault to actual iDRAC credential state before further automation.

- **Rundeck token error when using Rundeck backend**:
  - Ensure token env var named by `--rundeck-api-token-env` is populated.

---

## Contributing / future improvements

Potential improvements based on current code shape:

- Add integration tests against disposable Vault + mocked racadm service.
- Add optional retry/backoff policies for transient network/API failures.
- Add structured machine-readable error codes in reports.
- Add optional per-host checkpointing independent of report parsing.
- Add explicit redaction tests for sanitization behavior.
