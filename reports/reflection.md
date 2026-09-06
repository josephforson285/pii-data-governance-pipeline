# Reflection & Governance

PII Detection & Data Quality Validation Pipeline — 5,000 synthetic customer
records. Figures cite the reports in this directory.

## 1. Top five data quality issues

| Issue                                | Scale                   | Fix                            | Risk if unfixed                  |
| ------------------------------------ | ----------------------- | ------------------------------ | -------------------------------- |
| Sentinel nulls (`"N/A"`, whitespace) | 418 values, 5 columns   | Treated as missing             | Corrupts statistics and joins    |
| Non-standard phone formats                        | 1,036 rows, 8 formats   | Normalised; 34 quarantined     | Deduplication fails              |
| Non-standard dates                        | 787 values              | 748 repaired, 39 quarantined   | Wrong age/tenure or crashing                 |
| Invalid `account_status`             | 350 rows, 9 variants    | Alias mapping; 110 quarantined | Category fragmentation           |
| Duplicate `customer_id`              | 47 IDs, 50 surplus rows | Detected globally; quarantined | Join fan-out and double counting |

`income` illustrates the sentinel problem: 93 true nulls and 142 sentinel values. `dropna()` removes only the 93.

The most dangerous defects are silent ones: they produce plausible but incorrect results.

## 2. Risk assessment

Eight of ten columns contain personal data, and every record includes identifiers and contact information.

The highest-risk finding is **11 SSNs in free-text `address` fields**, alongside 18 phone numbers and 11 emails — 40 affected rows. Schema-based controls alone would miss them, so PII scanning runs across every column.

This broad scan produced 25,365 candidate matches, with 18,876 confirmed (**74.4% confirmation**). The false positives are retained with reasons rather than reducing detection sensitivity.

`customer_id` is also personal data because it directly links records back to individuals.


## 3. Masking trade-offs

Before masking, **100% of cleaned records were unique on quasi-identifiers**. After masking, **47.8% remain unique**.

<!-- An earlier result of 1.2% was misleading because it measured only explicitly masked columns. Including untouched `created_date` showed uniqueness was actually **99.7%**. Generalising that field to year reduced it to 47.8%. -->

<!-- **Privacy risk must be measured over every released attribute, not only the fields labelled sensitive.** -->

Masking retains cohort, income-band, provider, tenure and join analysis, but removes individual contact, exact age, income and geographic detail.

I would not release this openly. `customer_id` still links to the source and 47.8% uniqueness is too high. Wider generalisation and removal of linkage keys would be required, followed by re-measurement.

## 4. Validation strategy

Rules are defined in `config/rules.yml`, allowing policy changes without code changes.

Validation runs before and after cleaning:

**3,527 failures across 2,658 rows → 0**

Against 3,670 planted defects, detection achieved:

* **100% recall**
* **97.0% attribution**
* **90.7% macro attribution**
* **100% specificity** on 2,261 clean rows

Specificity matters because quarantining every row would also produce 100% recall.


The masked release is therefore re-scanned by `verify_release` before publication.

<!-- **A control should not depend on earlier stages discarding the evidence it needs.** -->


## 5. Production operations

The pipeline processes 5,000 rows in about 1.5 seconds, returns non-zero on failure, and writes an execution report even when a run fails.

Every run checks:

`rows_in == rows_out + rows_quarantined`

Post-clean validation also gates publication.

The largest operational gaps are:

**Retention.** Raw, cleaned, quarantined and masked copies are retained with no deletion workflow yet.

**Quarantine ownership.** Overall, data is not planned to be retained indefinitely.  

## 6. Lessons learned

**Do not “repair” values by guessing.** `clean_name()` removed non-ASCII characters, turning `José` into `Jos` and `Nguyễn` into `Nguyn`. Likewise, `int(float(x))` could turn `"12.9"` into `12`.

The rule is simple: repair only when the intended value is recoverable; otherwise quarantine it.

**Verify controls independently.** The first release check scanned only columns configured for masking, meaning removing a masking rule also removed its verification.

**Configuration must match execution.** `dob_before_created` existed in `rules.yml` but was never enforced.

**Reports are part of the data boundary.** Early reports included raw phone numbers and dates of birth as examples, leaking the same data the pipeline was designed to protect.

## Governance controls 

| Risk                          | Control                                                  | GDPR basis            |
| ----------------------------- | -------------------------------------------------------- | --------------------- |
| PII in free text              | Scan content at ingest                                   | Art. 32               |
| 47.8% release uniqueness      | Measure all released attributes; generalise to threshold | Recital 26            |
| `customer_id` links to source | Treat masked data as personal data                       | Recital 26            |
| Multiple copies, no deletion  | Retention and erasure workflow                           | Art. 5(1)(e), Art. 17 |
| Unowned quarantine            | Steward, SLA and disposal policy                         | Art. 5(2)             |
| PII in reports                | Redact generated artifacts                               | Art. 25               |
| Destructive repairs           | Quarantine unrecoverable values                          | Art. 5(1)(d)          |
| Unverified masking            | Re-scan release and fail on residual PII                 | Art. 25               |
