# Reflection & Governance

PII Detection & Data Quality Validation Pipeline — 5,000 synthetic customer
records. Figures cite the generated reports in this directory.

## 1. Top five data quality issues

| Issue | Scale | Fix | Impact if unfixed |
| --- | --- | --- | --- |
| Sentinel nulls (`"N/A"`, `"unknown"`, whitespace) | 442 values, 5 columns | Treated as missing at profiling | Survives `dropna()`; corrupts every mean and join |
| Non-standard phone formats | 8 shapes, 1,026 rows | Digits extracted, reformatted; 34 quarantined | One customer looks like several; dedup fails |
| Unparseable / non-standard dates | 789 values | 5-format parse; 750 repaired, 39 quarantined | Age and tenure calculations wrong or crashing |
| Invalid `account_status` | 350 rows, 9 variants | Case and alias mapping; 110 quarantined | `active` fragments into 4 buckets; reports off by 7% |
| Duplicate `customer_id` | 47 ids, 50 surplus rows | Quarantined; uniqueness enforced post-validation | Joins fan out; balances double-counted |

`income` illustrates the first one: 83 true nulls and 156 sentinels. A
completeness check reporting only `isna()` understates missingness by two
thirds, and `dropna()` removes the 83 while leaving the 156 in place.

Issues 1, 3 and 5 fail *silently*. A malformed email is visible the moment
someone sends to it; a sentinel null and a duplicated key produce
plausible-looking numbers that are wrong. That makes them more expensive, not
less, despite attracting less attention.

## 2. Risk assessment

Eight of ten columns carry personal data and all 5,000 records contain a name,
an identifier and contact details. No subset of this file is safe to release
unmasked.

I would escalate first the **eight US SSNs found inside the free-text
`address` field**, with 18 phone numbers and 14 emails — 40 rows. Volume
understates this. An SSN enables identity theft directly; the column is not
supposed to hold identifiers, so no schema-driven control would ever have
caught them; and their presence implies the upstream system accepts
unvalidated free text into a field treated as low-sensitivity downstream.

These surfaced only because the scan runs every pattern against every column
rather than trusting column names. That cost precision — 25,373 raw matches
reduced to 18,876 confirmed (74.4%) — and I kept the discards in the report
with a written reason each rather than narrowing the patterns until the output
looked clean. For a security control that trade is the right way round: a
false positive costs review time, a missed identifier is a breach.

`customer_id` is also personal data. It reads as harmless because it is an
integer, but it is a direct linkage key to the unmasked source, and under
Recital 26 pseudonymised data remains personal data.

**Article 33:** I would notify within 72 hours. 5,000 complete identity
records with home address and exact income, eight with an SSN, clears the
"risk to rights and freedoms" threshold without the assessment being arguable.

## 3. Masking trade-offs

Before masking, **100% of the 3,808 cleaned records were uniquely identifiable
on quasi-identifiers alone** — birth year, postal code and exact income, none
of them a direct identifier. After masking, 44 remain unique (1.2%).

That drop came from generalising the quasi-identifiers, not from masking
names, emails and phones. Had I implemented only the five rules the brief
lists, all 3,808 would still be uniquely identifiable to anyone holding a
second dataset with those attributes — a file that looks protected and offers
no protection against linkage.

Two rules I added for that reason: **address is replaced wholesale**, because
it is free text proven to contain leaked SSNs, so partial masking leaves them
in place; and **income is banded**, which costs exact financial statistics but
breaks the uniqueness exact values create.

Retained: age analysis, income segmentation, provider mix, tenure, joins.
Lost: contacting individuals, geographic analysis, exact income, exact age.

**Would I release the 44?** Not unrestricted. 1.2% is a large improvement and
still not anonymity, and `customer_id` links back to source. I would release
under contract to a named recipient with access control and purpose
limitation. If it had to go out openly, I would suppress those 44 or widen the
bands until they group — a control that protects 98.8% of people and silently
exposes the rest is not one I would want to defend afterwards.

## 4. Validation strategy

Rules live in `config/rules.yml` and translate to pandera checks, so policy
changes without touching pipeline code. Validation runs before and after
cleaning: **3,510 failures across 2,633 rows went to zero**, and that delta is
the evidence. A single post-clean pass proves only that clean data is clean,
which is true by construction.

Two details made it usable. `lazy=True`, without which pandera aborts on the
first bad value and yields a traceback instead of a report. And separating
uncoercible values from absent ones — 489 `date_of_birth` values were present
and unparseable, 71 genuinely blank, needing different fixes. That 489 matched
the profiler's independent count exactly.

Measured against a held-out manifest of 3,670 planted defects: **99.6% recall,
96.4% attribution**. My first version reported only attribution and showed
`income_non_numeric` at 0%, which looked like a broken detector. It was not —
`"$52,000"` is repaired, so the "unparseable" check correctly never fires.
Splitting the metric turned an apparent failure into a measurement.

The real finding: **13 rows with duplicate ids reached the output without the
dedup check firing**, yet the file has zero duplicates — the colliding row had
already been quarantined for an unrelated reason. The output is correct but
the property is fragile, because that scan's reach depends on how much the
previous stage rejected. A scan whose coverage moves with upstream policy is
not an invariant; uniqueness must be enforced at the output, which
post-validation does.

One rule I would add: a cross-field check that `date_of_birth` precedes
`created_date`. Every current rule validates a column in isolation, so a
customer created before they were born passes all of them.

## 5. Production operations

5,000 rows in 0.80s, non-zero exit on failure, execution report written even
when a run dies. Every run asserts `rows_in == rows_out + rows_quarantined`.

**Retention is the gap I would close first.** The pipeline creates four copies
of every subject's personal data — raw, cleaned, quarantined, masked — and
deletes none. Article 5(1)(e) requires storage limitation and Article 17 a
right to erasure; neither is satisfiable, since there is no mechanism to find
a subject in the quarantine file, let alone remove them.

**Quarantine ownership is second.** 1,192 rows per run (23.8%) are set aside
with a reason. That is defensible engineering and an indefensible operating
model with nobody assigned. It needs a named steward, a remediation SLA and a
disposal rule — otherwise quarantine is a slower way of deleting data while
feeling responsible about it.

Also open: no alerting threshold, so a run where quarantine jumps to 60%
succeeds quietly; and cleaning is a row-wise loop that will not hold at 10M
rows.

## 6. Lessons learned

Generating the dataset with a held-out defect manifest let me measure
detection rather than assume it — that is where the deduplication finding came
from, and reading the output would not have surfaced it.

Loading the CSV as text mattered more than expected. Type inference would have
quietly repaired the defects the profiler exists to find: a negative income
becomes a valid float, `invalid_date` becomes `NaT` and is indistinguishable
from a blank.

Quantifying a policy's cost changed how I see validation rules. Retention is
76.2%, and 442 of the 1,192 quarantined rows fail only on a blank optional
field; a tiered policy would retain 85%. I kept the strict rule because the
brief declares those fields mandatory, but reporting the number turned an
unexamined default into a decision someone can argue with. A validation rule
is a business choice wearing technical clothing.

The mistake worth recording: I originally wrote raw phone numbers and dates of
birth into `data_quality_report.txt` as format examples. Nothing was disclosed
because the data is synthetic, but a governance report that leaks the data it
audits is exactly the failure this project exists to catch — and I did it
while building the tool to prevent it. Handling rules apply to the artifacts,
not just the dataset.

## Governance controls recommended

| Risk identified | Control | GDPR basis |
| --- | --- | --- |
| Direct identifiers in free text (40 rows, 8 SSNs) | Content scanning on ingest, not schema-driven masking | Art. 32 |
| 100% of records unique on quasi-identifiers | Generalise quasi-identifiers; test against a k threshold | Recital 26 |
| `customer_id` links extract to source | Treat masked extract as personal data; release under contract | Recital 26 |
| Four copies, no deletion | Retention schedule and erasure across all artifacts | Art. 5(1)(e), Art. 17 |
| 1,192 quarantined rows, no owner | Named steward, remediation SLA, disposal rule | Art. 5(2) |
| Reports quoted raw PII | Redaction applied to artifacts as well as data | Art. 25 |
| No alerting on degradation | Quarantine-rate threshold; fail the run when exceeded | Art. 5(1)(d) |
