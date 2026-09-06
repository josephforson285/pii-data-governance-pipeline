# PII Detection & Data Quality Pipeline

Profiles a raw customer dataset, detects PII, validates it against a declared
schema, remediates what it can and masks the rest before the data is shared.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src
```

## Usage

```bash
python -m pipeline generate      # synthetic raw dataset + defect manifest
python -m pipeline run           # every stage, all reports
python -m pipeline score         # detection measured against the manifest
pytest                           # 149 tests
```

<!-- To start from nothing - useful for a demo, or to prove the numbers reproduce:

```bash
./demo-reset.sh --run            # clear every generated artifact, then rebuild
```

It verifies the interpreter before deleting anything, and refuses to run if
`reports/reflection.md` has uncommitted changes - that file is written by hand
and is the only one nothing regenerates. It picks up `.venv/bin/python`
automatically; point it elsewhere with `PYTHON=/path/to/python ./demo-reset.sh`.

Individual stages (`profile`, `detect`, `validate`, `clean`, `mask`) can be run
on their own. `run` exits non-zero if any stage fails and still writes the
execution report. -->

## Pipeline

```
load -> profile -> detect PII -> validate(pre) -> clean -> validate(post)
     -> publish -> mask -> verify_release -> publish_masked
```

Two ordering choices are intentional:

**PII detection runs on the raw file.** Breach exposure is a property of what
landed on disk. Scanning after cleaning would understate it by every
quarantined row.

**Validation runs on both sides.** A single post-clean pass only proves the
clean data is clean. The pre/post delta is what shows remediation worked.

## Results

| Measure | Value |
| --- | --- |
| Rows in / cleaned / quarantined | 5,000 / 3,682 / 1,318 |
| Rule failures, pre -> post | 3,527 -> 0 |
| Rows with PII leaked into free text | 40, incl. 11 SSNs |
| Uniquely re-identifiable, pre -> post mask | 100% -> 47.8% |
| Detection recall / attribution | 100% / 97.0% |

## Design notes

* **Load as text:** preserves malformed values until cleaning.
* **Separate nulls and sentinels:** `"N/A"`, `"unknown"`, and whitespace are not true nulls.
* **Never drop rows silently:** quarantined rows include a reason and must satisfy `rows_in == rows_out + rows_quarantined`.
* **Measure the full release:** re-identification risk includes unmasked quasi-identifiers such as `created_date`.
* **Centralize policy:** validation, masking, thresholds, and sensitive fields live in `config/rules.yml`.
* **Only repair recoverable values:** ambiguous values are quarantined rather than forced valid.
* **Keep scoring independent:** only `score` reads the planted-defect manifest.
* **Verify before publishing:** cleaned and masked outputs are blocked if validation fails.
* **Reproduce from seed:** `reference_date` keeps date-dependent output deterministic.


## Layout

| Path               | Purpose                            |
| ------------------ | ---------------------------------- |
| `src/pipeline/`    | Pipeline stages                    |
| `config/rules.yml` | Rules and masking policy           |
| `data/`            | Raw, cleaned, and quarantined data |
| `reports/`         | Generated reports                  |
| `tests/`           | Test suite                         |


## Data handling

Raw, cleaned, and quarantined files contain unmasked PII and are gitignored.

Only the masked extract is committed.

`reports/masked_sample.txt` intentionally shows unmasked synthetic values as evidence that masking works. Production data would be treated as restricted.

## Reports

| File | Part |
| --- | --- |
| `data_quality_report.txt` | 1 |
| `pii_detection_report.txt` | 2 |
| `validation_results.txt` | 3 |
| `cleaning_log.txt` | 4 |
| `masked_sample.txt` | 5 |
| `pipeline_execution_report.txt` | 6 |
| `reflection.md` | 7 |
| `detection_scorecard.txt` | extra |
