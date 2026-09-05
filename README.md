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
pytest                           # 34 tests
```

Individual stages (`profile`, `detect`, `validate`, `clean`, `mask`) can be run
on their own. `run` exits non-zero if any stage fails and still writes the
execution report.

## Pipeline

```
load -> profile -> detect PII -> validate(pre) -> clean -> validate(post) -> mask
```

Two ordering decisions differ from the obvious one:

**PII detection runs on the raw file.** Breach exposure is a property of what
landed on disk. Scanning after cleaning would understate it by every
quarantined row.

**Validation runs on both sides.** A single post-clean pass only proves the
clean data is clean. The pre/post delta is what shows remediation worked.

## Results

| Measure | Value |
| --- | --- |
| Rows in / cleaned / quarantined | 5,000 / 3,808 / 1,192 |
| Rule failures, pre -> post | 3,510 -> 0 |
| Rows with PII leaked into free text | 40, incl. 8 SSNs |
| Uniquely re-identifiable, pre -> post mask | 100% -> 1.2% |
| Detection recall / attribution | 99.6% / 96.4% |

## Design notes

**Load as text.** Pandas would coerce a negative income into a valid float and
`invalid_date` into `NaT` on read, erasing the defects the profiler exists to
find. Coercion happens in cleaning, after the damage is recorded.

**Nulls and sentinels are counted apart.** `"N/A"`, `"unknown"` and whitespace
read as present and survive `dropna()`. Reporting them as one number with true
nulls reports the wrong number.

**Nothing is dropped.** Rejected rows go to `data/rejects/quarantine.csv` with
a reason. The run asserts `rows_in == rows_out + rows_quarantined` and aborts
on a mismatch, so a row lost to a swallowed exception cannot look like a row
that was never there.

**Masking is measured, not asserted.** Masking names and emails leaves 100% of
records uniquely re-identifiable on birth year, postal code and income. The
drop to 1.2% comes from generalising those quasi-identifiers instead.

**The scorer cannot see the answer key.** `generate` writes a manifest of every
planted defect. Nothing under `run` reads it; only `score` does.

## Layout

| Path | Purpose |
| --- | --- |
| `src/pipeline/` | One module per stage, plus `report.py` for rendering |
| `config/rules.yml` | Validation rules and remediation policy |
| `data/` | Raw, cleaned and quarantined data (gitignored) |
| `reports/` | Generated deliverables |
| `tests/` | Weighted toward masking |

## Data handling

`data/raw/`, `customers_cleaned.csv` and `data/rejects/` hold unmasked PII and
are gitignored. The dataset is synthetic and reproducible from a seed, so
nothing is lost by excluding it. Only the masked extract is committed.

`reports/masked_sample.txt` shows unmasked values by design - it is the
evidence the control works. It is committed only because the data is
synthetic; against production data it would be classified restricted.

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
