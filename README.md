# Dell iDRAC Batch Password Rotator

## Overview

This project provides a production-oriented Python CLI to rotate Dell iDRAC account passwords in batch across many servers.

It exists to solve a common operational risk in infrastructure teams: credential drift between hardware management interfaces (iDRAC) and centralized secret stores. In this workflow, HashiCorp Vault is the source of truth for credential retrieval and persistence, while `racadm` (or an enterprise job runner) is used to apply password changes on each iDRAC endpoint.

The tool is intentionally designed so Vault is updated **only after** a successful password change on the target iDRAC. Before writing, it also performs **Vault pre-flight validation** of secret metadata/state (and version expectations where applicable) to reduce unsafe writes. The CLI can run directly on an automation host or through **Rundeck** as an enterprise execution/orchestration layer.

## Key Features

- Batch password rotation from CSV input.
- Unique, random password generation per server.
- HashiCorp Vault KV v2 integration for read/write secret workflows.
- Pre-flight Vault secret validation before update (metadata/state checks before write).
- Safer secret-state/version checks before write when rotating in-place (same read/write path).
- Dell `racadm` integration for direct iDRAC password updates.
- Rundeck integration for controlled enterprise execution via API-driven job runs.
- Compatibility with centralized scheduling and operational runbooks (local CLI or Rundeck job orchestration).
- `--dry-run` mode for safe validation without iDRAC or Vault writes.
- Simulation-friendly architecture via mocked Vault and racadm runners in tests.
- Concurrency control with configurable thread pool (`--concurrency`).
- Structured reporting to both CSV and JSON.
- Resume support (`--resume-from-report`) to skip prior successful hosts.
- Explicit partial-failure detection (`CRITICAL_PARTIAL_FAILURE`) when iDRAC changes but Vault update fails.
- Sanitized, audit-friendly logging that avoids secret disclosure.
- Explicit **bootstrap exception mode** for first-run rotations when current passwords are not yet in Vault.

## Architecture Summary

Main components:

- **CLI/config (`argparse`)**: Parses runtime flags (input file, filters, concurrency, timeout, dry-run, reporting, resume behavior).
- **CSV loader/validator**: Enforces required columns, non-empty fields, and duplicate-host prevention.
- **Vault client (`VaultKv2Client`)**: Reads and writes password fields from/to KV v2 paths with metadata/state pre-flight checks and CAS-safe updates.
- **Password policy engine (`generate_password`)**: Produces strong random passwords with configurable length and special-character set.
- **Execution backend**:
  - **Local mode**: `run_racadm_password_change` executes `racadm` directly.
  - **Rundeck mode**: `RundeckJobRunner` calls Rundeck API to launch and monitor a password-change job per host.
- **Orchestrator (`orchestrate`)**: Applies filters, resume behavior, concurrency/fail-fast execution, summary generation, and exit code logic.
- **Reporting (`write_reports`)**: Emits per-host result rows and aggregate summary in JSON and CSV.
- **Simulation backends**: Test-time stubs/mocks for Vault and execution runners to simulate success, failure, and partial failure safely.

Operational flow summary:

- Vault remains the system of record for credential state.
- The runner (local `racadm` or Rundeck job) performs the iDRAC password change.
- Vault pre-flight validation is executed immediately before write in the post-change stage.
- Rundeck, when used, is an orchestration/execution layer around this CLI workflow; it is **not** the credential source of truth.

## Safe Workflow

The implemented safe sequence is:

1. **Read current credential state from Vault** (`current_password_vault_path`) in normal mode, including the current secret version.
2. **Generate a candidate new password in memory** (never persisted in plaintext logs).
3. **Apply password change** using the configured execution backend:
   - local `racadm`, or
   - Rundeck job execution (which performs the change externally).
4. **If change succeeds, run Vault pre-flight validation before write** against `new_password_vault_path`:
   - checks metadata can be read,
   - checks latest version state is writable (not deleted/destroyed),
   - when writing back to the same path used for the read, checks observed version still matches expected version.
5. **Write new secret to Vault only after successful change + pre-flight pass**.
6. **Handle partial failures explicitly**:
   - if password change succeeded but Vault validation/write failed, host is marked `CRITICAL_PARTIAL_FAILURE` and requires urgent operator remediation.

This sequence is the core control that reduces drift while still surfacing high-risk split-brain conditions.

## Vault Pre-flight Validation

### What it means in this project

Before writing a new password to Vault, the tool performs a pre-flight metadata/state check on the target KV v2 path.

### Why it exists

This check reduces the chance of writing into an unexpected secret state (for example, drifted version state or non-writable latest version) and makes write safety explicit.

### What is checked before write

Current implementation validates:

- Secret metadata readability for the target path.
- `current_version` sanity in metadata.
- Latest version state is writable (not soft-deleted and not destroyed).
- Optional version expectation on in-place rotation:
  - If `new_password_vault_path == current_password_vault_path`, the tool compares expected version (captured at read time) with observed `current_version` at pre-flight time.

### Secret existence / overwrite safety behavior

- If target path does not exist:
  - allowed for writes where no specific prior version is expected (new secret creation path),
  - rejected when a specific existing version is expected.
- Write is still performed with KV v2 CAS semantics after pre-flight (existing data merged; password field updated).

### How this reduces unsafe writes

- Detects version drift before write on in-place rotations.
- Prevents writes to paths where latest version state is marked deleted/destroyed.
- Fails early with actionable error context instead of silently overwriting unexpected state.

### Assumptions and limitations

- Version drift comparison is currently strict only for in-place updates (same read/write path).
- If read/write paths differ, version expectation is not enforced between those paths.
- Validation depends on Vault KV v2 metadata behavior and policy permissions.

## Bootstrap Exception Mode (Initial Rollout Only)

Use bootstrap mode only for the first rollout when:

- all target iDRACs still share the same current password, and
- current passwords are not yet stored in Vault.

When bootstrap mode is enabled:

1. The tool does **not** read `current_password_vault_path` per server from Vault.
2. It reads one shared current password from an environment variable at runtime.
3. It still generates a unique new password per server.
4. It still writes each new password to that server's `new_password_vault_path` after successful password-change execution.
5. If password change fails, no Vault write occurs.
6. If Vault write fails after successful password change, status is `CRITICAL_PARTIAL_FAILURE` with remediation guidance.

> Security note: do not pass shared passwords as direct CLI values. Prefer env vars so secrets are not exposed in shell history/process lists.

After the initial bootstrap rotation completes, migrate immediately back to the standard per-server Vault-read mode.

## Rundeck Integration

Rundeck support allows this CLI to run inside an enterprise job-runner model while preserving the tool's Vault-centric state flow and reporting semantics.

### Why Rundeck is useful here

- Centralized scheduling for maintenance windows.
- Controlled, permissioned operator execution.
- Scoped execution by site/environment via job options.
- Standardized audit trail of who ran what and when.
- Alignment with existing operations runbooks.

### Operational model

- This CLI remains the workflow controller and report producer.
- With `--job-runner rundeck`, per-host password change is delegated to a Rundeck job via API.
- Rundeck job executes the change logic in your approved execution environment.
- CLI polls Rundeck execution state (`SUCCEEDED`/`FAILED`/`ABORTED`/`TIMEDOUT`) and continues normal post-change flow.
- Vault is still read/written by this CLI; Rundeck is not the source of truth.

### Typical enterprise use cases

- Scheduled rotation windows (nightly/weekly/monthly policy windows).
- Controlled production job execution with operator approvals.
- Scoped runs by site/environment (`--site-filter`, `--environment-filter`).
- Operator-triggered incident or emergency rotations.
- Audit-friendly execution history with per-run reports retained as artifacts.

### Practical workflow considerations in Rundeck

- Store Vault/Rundeck tokens in secure key storage, then expose to runtime env vars only for the job context.
- Pass input CSV and report output locations explicitly in job step arguments.
- Ensure job working directory/path mapping is deterministic.
- Capture generated JSON/CSV reports as Rundeck artifacts for post-run review.
- Do not echo secret-bearing env vars/options to logs.

## Project Structure

```text
.
├── idrac_password_rotator.py        # Main CLI, orchestration, Vault/racadm/Rundeck integration, reporting
├── requirements.txt                 # Python dependencies
├── sample_idrac_batch.csv           # Example input dataset
├── tests/
│   └── test_idrac_password_rotator.py  # Unit tests (CSV validation, flow outcomes, fail-fast)
└── README.md                        # This documentation
```

## Requirements

- **Python**: 3.9+ recommended.
- **Execution backend**:
  - Local mode: `racadm` binary installed and available in `PATH`.
  - Rundeck mode: reachable Rundeck API endpoint and executable job definition.
- **Vault access**:
  - Network reachability to Vault.
  - Valid token with read/write access to relevant KV v2 paths.
- **Operating system**: Linux automation host is assumed (or equivalent environment where Python and backend tools are available).

## Installation

```bash
git clone <REPO_URL>
cd pwd_idrac_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify `racadm` availability before running production rotations in local mode:

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
- `--job-runner` (`local` or `rundeck`) to select local racadm vs enterprise job orchestration.
- `--password-length` and `--password-specials` for password policy tuning.
- `--timeout` for per-host backend timeout.
- `--bootstrap-shared-current-password` to enable bootstrap exception mode.
- `--shared-current-password-env` to select env var name for bootstrap shared current password (default: `IDRAC_SHARED_CURRENT_PASSWORD`).

### Rundeck Job Runner (Optional)

When `--job-runner rundeck` is enabled, the tool triggers a Rundeck job per host and waits for completion instead of executing local `racadm`.

Required:

- `--rundeck-url`
- `--rundeck-job-id`
- `--rundeck-api-token-env` (defaults to `RUNDECK_API_TOKEN`)

Expected Rundeck job option names:

- `idrac_host`
- `idrac_username`
- `target_account_id`
- `target_account_username`
- `current_password`
- `new_password`

Optional:

- `--rundeck-insecure-skip-tls-verify` for non-production TLS exceptions.

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

In **normal mode** (default), `current_password_vault_path` is required and used.

In **bootstrap mode** (`--bootstrap-shared-current-password`), `current_password_vault_path` can be blank or omitted from CSV; it is ignored for authentication during that first rotation run.

### Sample CSV

```csv
idrac_host,idrac_username,current_password_vault_path,target_account_username,target_account_id,new_password_vault_path,site,environment
10.20.1.15,root,idrac/prod/site-a/r740-01/current,root,2,idrac/prod/site-a/r740-01/current,dc-a,prod
10.20.1.16,root,idrac/prod/site-a/r740-02/current,root,2,idrac/prod/site-a/r740-02/current,dc-a,prod
10.30.4.10,root,idrac/stage/site-b/r650-01/current,root,2,idrac/stage/site-b/r650-01/current,dc-b,stage
```

### Field Meaning

- `idrac_host`: iDRAC endpoint hostname or IP.
- `idrac_username`: Administrative iDRAC login used for password-change execution.
- `current_password_vault_path`: Vault KV path to read current password from.
- `target_account_username`: Intended iDRAC account username being rotated (metadata/traceability).
- `target_account_id`: iDRAC user slot/account ID used in password-change command (`iDRAC.Users.<ID>.Password`).
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

### 3) Production run (local racadm backend)

```bash
python idrac_password_rotator.py \
  --input-file batch_prod.csv \
  --concurrency 6 \
  --timeout 90 \
  --vault-mount secret \
  --vault-password-key password \
  --report-file reports/prod_full
```

### 3b) Initial bootstrap rollout run (shared current password from env)

```bash
export IDRAC_SHARED_CURRENT_PASSWORD="<shared-existing-idrac-password>"

python idrac_password_rotator.py \
  --input-file batch_initial_bootstrap.csv \
  --bootstrap-shared-current-password \
  --shared-current-password-env IDRAC_SHARED_CURRENT_PASSWORD \
  --concurrency 6 \
  --timeout 90 \
  --vault-mount secret \
  --vault-password-key password \
  --report-file reports/bootstrap_initial
```

If bootstrap mode is enabled and the configured env var is missing, the tool fails fast before any host processing.

### 4) Filtered run by site/environment

```bash
python idrac_password_rotator.py \
  --input-file batch_all_sites.csv \
  --site-filter dc-a \
  --environment-filter prod \
  --report-file reports/dc-a_prod
```

### 5) Rundeck-backed execution

```bash
export RUNDECK_API_TOKEN="<rundeck-api-token>"

python idrac_password_rotator.py \
  --input-file batch_prod.csv \
  --job-runner rundeck \
  --rundeck-url https://rundeck.example.internal \
  --rundeck-job-id 7b7f6d8a-0000-1111-2222-0123456789ab \
  --rundeck-api-token-env RUNDECK_API_TOKEN \
  --site-filter dc-a \
  --environment-filter prod \
  --concurrency 4 \
  --timeout 120 \
  --report-file reports/rundeck_dc-a_prod
```

### 6) Rundeck job-step style invocation example

```bash
python idrac_password_rotator.py \
  --input-file "${RD_OPTION_INPUT_CSV}" \
  --job-runner rundeck \
  --rundeck-url "${RD_OPTION_RUNDECK_URL}" \
  --rundeck-job-id "${RD_OPTION_RUNDECK_JOB_ID}" \
  --rundeck-api-token-env RUNDECK_API_TOKEN \
  --site-filter "${RD_OPTION_SITE}" \
  --environment-filter "${RD_OPTION_ENVIRONMENT}" \
  --report-file "${RD_JOB_LOGLEVEL:-reports}/rotation_${RD_JOB_EXECID}"
```

### 7) Simulation run (safe pre-production verification)

```bash
# Operational simulation using dry-run
python idrac_password_rotator.py \
  --input-file sample_idrac_batch.csv \
  --dry-run \
  --limit 20 \
  --report-file reports/sim_dryrun
```

### 8) Resume from previous report

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
   - Does **not** execute password-change operations.

2. **Test harness simulation (pytest with stubs/mocks)**
   - Replaces Vault and backend execution calls with controlled fake backends.
   - Supports deterministic failure injection (e.g., racadm failure, Vault write failure after password change success).
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
- `idrac_password_changed`: whether password-change execution succeeded.
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
  - Password changed and Vault updated successfully.
- `FAILED`
  - Rotation failed before full completion (Vault read issue, password policy issue, execution backend failure, timeout, etc.).
- `CRITICAL_PARTIAL_FAILURE`
  - Password changed, but Vault update failed. Immediate remediation required.
- `DRY_RUN_SKIPPED`
  - Dry-run mode; host validated in workflow but no state-changing operations executed.

## Failure Handling and Recovery

### Vault read failure

- **Symptom**: `FAILED` with Vault read/auth/path message.
- **Action**:
  - Validate token permissions and TTL.
  - Validate KV mount/path and key (`--vault-password-key`).
  - Re-run for affected scope.

### Vault pre-flight validation failure

- **Symptom**: `CRITICAL_PARTIAL_FAILURE` after successful password change, with metadata/version/state validation error.
- **Action**:
  - Treat as urgent credential-state mismatch.
  - Verify actual current secret state/version in Vault.
  - Reconcile secret under approved break-glass/change process before retry.

### Backend execution failure (`racadm` or Rundeck)

- **Symptom**: `FAILED`, `idrac_password_changed=false`, `vault_updated=false`.
- **Action**:
  - For local mode: check DNS/network reachability, credentials, account ID, and racadm tooling.
  - For Rundeck mode: inspect Rundeck execution output/state and worker-node access.
  - Reproduce manually in maintenance context if needed.

### Timeout

- **Symptom**: `FAILED` with timeout text.
- **Action**:
  - Increase `--timeout` for slow networks/external job latency.
  - Reduce `--concurrency` to avoid saturation.
  - Retry affected subset.

### Vault write failure after successful password change

- **Symptom**: `CRITICAL_PARTIAL_FAILURE`, `idrac_password_changed=true`, `vault_updated=false`.
- **Action (urgent)**:
  1. Open incident/change exception immediately.
  2. Confirm new iDRAC credential via controlled access.
  3. Update Vault path with verified credential under break-glass procedure.
  4. Record remediation evidence and close incident.

### Rundeck operator interpretation

- Non-zero CLI exit means the run needs investigation:
  - `1`: one or more hosts failed (no confirmed split-state event).
  - `2`: at least one critical partial failure (password changed but Vault not updated).
- For orchestrated jobs, map non-zero exit to alerting/escalation policy in Rundeck.

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
- Backend failure handling.
- Critical partial failure handling when Vault write fails post-change.
- Dry-run per-host behavior.
- Fail-fast orchestration behavior.

Mocking strategy:

- Vault operations are replaced with in-memory stub classes.
- Backend execution is replaced with fake runner responses.
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
- Pre-flight Vault validation helps enforce safer secret lifecycle handling by checking metadata/state before write.
- Do not hardcode credentials in code, CSV, or shell history.
- Use least-privilege Vault token scoped only to required KV paths and operations.
- Prefer short-lived tokens and controlled execution context.
- If using Rundeck:
  - store tokens/secrets in secure key storage,
  - avoid printing env vars/options containing secrets,
  - restrict job and node permissions by least privilege,
  - control who can view job logs and artifacts.
- Protect input CSV and report artifacts (`*.json`, `*.csv`) because they contain host inventory and operational metadata.
- In job-runner environments, ensure artifact paths and retention policies follow internal data-handling requirements.
- Validate exact local `racadm` command syntax in a lab environment before production.
- Confirm generated password policy aligns with active Dell iDRAC firmware complexity rules.
- Restrict who can run this tool and access result artifacts.

## Known Assumptions and Environment-Specific Validation

Before production, validate these assumptions explicitly:

1. **racadm syntax compatibility (local mode)**
   - Command format for your firmware/tooling matches implementation (`set iDRAC.Users.<ID>.Password ...`).
2. **Vault KV v2 semantics**
   - Target mount is KV v2 and supports metadata and CAS behavior as expected.
3. **iDRAC account ID behavior**
   - `target_account_id` maps correctly to intended user slot across hardware generations.
4. **Password policy compatibility**
   - Generated length/special character set are accepted by all target iDRAC versions.
5. **Network and timeout envelope**
   - Execution host can reach Vault and, depending on backend, iDRAC endpoints or Rundeck API.
6. **Concurrency tolerance**
   - `--concurrency` does not overwhelm network devices, iDRAC interfaces, Vault, or Rundeck execution capacity.

## Troubleshooting

- **`CSV validation error` at startup**
  - Check header names and required non-empty fields.
  - Ensure no duplicate `idrac_host` values.

- **Vault pre-flight validation failure before write**
  - Verify target path metadata is accessible and writable.
  - Check for deleted/destroyed latest secret version.
  - Confirm no concurrent process updated the same path if in-place rotation is used.

- **Vault version/state mismatch (`expected ... observed ...`)**
  - Another process may have updated the same secret between read and write.
  - Re-read latest secret state and re-run controlled rotation for that host.

- **`Vault authentication failed`**
  - Validate `VAULT_ADDR`, `VAULT_TOKEN`, and optional `VAULT_NAMESPACE`.
  - Confirm token policy and namespace scope.

- **Rundeck environment variable issues**
  - Confirm token env var name matches `--rundeck-api-token-env`.
  - Ensure Rundeck job securely injects variables into the CLI process environment.

- **Missing file paths in Rundeck-run context**
  - Use absolute paths for `--input-file` and `--report-file` when job working directory is not guaranteed.
  - Validate that runner node has access to mounted storage locations.

- **Report path permission problems in job-runner environments**
  - Ensure CLI process user can create parent directories/write report files.
  - Route reports to approved writable artifact directories.

- **`racadm binary not found in PATH` (local mode)**
  - Install/enable RACADM tooling and verify with `which racadm`.

- **Frequent backend timeouts/failures**
  - Lower concurrency, increase timeout, and verify network ACL/firewall paths.

## Future Improvements

Potential enhancements for enterprise adoption (beyond the currently implemented Vault pre-flight checks and Rundeck runner support):

- Vault AppRole/JWT/OIDC auth support (reducing static token usage).
- Cross-process lock/coordination patterns for very high-concurrency rotations.
- Standardized Rundeck job-option templates and project defaults.
- Approval workflow integration for high-sensitivity production scopes.
- Scheduled rotation policy packs tied to environment/site governance.
- Metrics export (Prometheus/OpenTelemetry) for run observability.
- Optional encrypted-at-rest report outputs.
