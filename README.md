# PII Detection & Data Quality Pipeline

Profiles a raw customer dataset, detects PII, validates it against a schema,
remediates quality issues and masks sensitive fields before sharing.

## Setup

```bash
pip install -r requirements.txt
export PYTHONPATH=src
```

## Usage

```bash
python -m pipeline generate          # build data/raw/customers_raw.csv
```

## Layout

| Path | Purpose |
| --- | --- |
| `src/pipeline/` | Pipeline stages |
| `config/rules.yml` | Validation rules |
| `data/` | Raw, cleaned and quarantined data (gitignored) |
| `reports/` | Generated reports |

## Data handling

`data/raw/`, `data/processed/customers_cleaned.csv` and `data/rejects/` hold
unmasked PII and are gitignored. The dataset is synthetic and reproducible from
a seed, so nothing is lost by excluding it. Only the masked extract is shared.
