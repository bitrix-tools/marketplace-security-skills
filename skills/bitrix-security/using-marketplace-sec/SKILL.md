---
name: using-marketplace-sec
description: "Use when running the full Marketplace security pre-submission flow for Bitrix modules: scan one module, review BUS severity, update the cumulative vulnerability journal, validate saved developer feedback, and summarize release readiness."
---

# Using Marketplace Security

Use this skill when a Bitrix module developer needs the full partner-side pre-submission process, not just a raw scan.

This skill is an orchestrator. It does not contain security-audit heuristics. Keep audit improvements in `scan`; keep BUS severity policy in `journal-review`; keep lifecycle state in `journal-update`.

## Inputs

- module path, for example `modules/vendor.module`
- optional previous `security-journal.json`
- optional final archive SHA-256

## Required Workflow

1. If a previous `security-journal.json` exists, prepare it as context for the scan. The scan skill may use it as `last-result.json`, but it must still verify findings against real code.
2. Run `scan <module_path>`.
   - Expected output: `reports/<module_code>.json`
3. Run `journal-review` on that scan output.
   - Recommended output: `reports/<module_code>.reviewed.json`
4. Run `journal-update`:

```bash
python3 <journal-update-skill>/scripts/update_journal.py \
  reports/<module_code>.reviewed.json \
  --previous reports/security-journal.json \
  --module-path <module_path> \
  --archive-sha256 <sha256> \
  --output reports/security-journal.json
```

For the first run, omit `--previous`.

5. Validate the journal:

```bash
python3 <journal-update-skill>/scripts/update_journal.py \
  --validate-only reports/security-journal.json
```

6. Launch the local journal UI. This is a required flow step, not an optional convenience. Use the updated reviewed scan and cumulative journal:

```bash
python3 tools/journal_ui_server.py \
  --reviewed reports/<module_code>.reviewed.json \
  --journal reports/security-journal.json \
  --host 127.0.0.1 \
  --port 8765
```

If port `8765` is already in use, pick the next free port. Open the resulting URL in the browser and verify the UI loads the latest `current_state` and finding count via `/api/data` or the visible metrics before reporting completion. Also verify that disposition counts (`false_positive`, `accepted_risk`, `open`) match both the top metrics and the per-card disposition state, because preserved developer feedback must come from the cumulative journal on repeat runs.

7. Report the final status from `current_state`, the UI URL, and the displayed finding counts:
   - `ready_for_submission`: no open findings and no unresolved dispositions
   - `blocked`: open high findings remain
   - `needs_review`: open lower-severity findings or partner dispositions remain

## Output Artifacts

- `reports/<module_code>.json` — raw scan output
- `reports/<module_code>.reviewed.json` — BUS-aware reviewed scan
- `reports/security-journal.json` — cumulative submission artifact
- local journal UI URL — required review interface for developer feedback

Only `reports/security-journal.json` is the stable partner submission artifact. The raw and reviewed scan files are intermediate evidence and may be requested for debugging.

## Boundaries

- Do not modify `scan` behavior from this skill.
- Do not manually edit reviewed severity; use `journal-review`.
- Do not manually update lifecycle counters; use `journal-update`.
- Do not consider the full flow complete until the local journal UI has been launched and checked against the latest journal.
- If the updater cannot classify a lifecycle transition, stop and explain the exact ambiguous case instead of inventing journal state.
