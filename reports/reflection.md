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
| Duplicate `customer_id` | 47 ids, 50 surplus rows | Detected across the whole input; duplicates quarantined | Joins fan out; balances double-counted |

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
rather than trusting column names. That cost specificity — 25,373 raw matches
reduced to 18,876 confirmed, a **74.4% confirmation rate** — and I kept the
discards in the report with a written reason each rather than narrowing the
patterns until the output looked clean. For a security control that trade is
the right way round: a false positive costs review time, a missed identifier
is a breach. It is a confirmation rate rather than precision, because these
are regex hits filtered by declared policy, not matches labelled against
ground truth.

`customer_id` is also personal data. It reads as harmless because it is an
integer, but it is a direct linkage key to the unmasked source, and under
Recital 26 pseudonymised data remains personal data.

**On Article 33:** the factors a notification assessment would weigh are all
present — 5,000 complete identity records, home address and income for each,
national identifiers for eight. Whether the threshold is met is a formal risk
assessment rather than something the pipeline determines, but I would expect
this to clear it.

## 3. Masking trade-offs

Before masking, **100% of the 3,684 cleaned records were uniquely identifiable
on quasi-identifiers alone** — none of which is a direct identifier. After
masking, 1,775 remain unique: **48.2%**.

That second number was originally 1.2%, and it was wrong. I had computed
post-mask uniqueness over the *masked* columns only, ignoring `created_date`,
which was released untouched because I had classified it as operational
non-PII. It has 1,957 distinct values across 3,684 rows — roughly one per two
customers. Including it, masking took uniqueness from 100% to **99.7%**: the
controls had achieved almost nothing, while the report claimed a 99-point
improvement.

The fix was to generalise `created_date` to its year and reclassify it as a
quasi-identifier, which brings the real figure to 48.2%. The lesson is the
one worth keeping: **a privacy metric computed over a subset of what you
release is not a privacy metric.** The measurement has to cover every
attribute that actually leaves the building, including the ones you decided
were boring.

| Retained | Lost |
| --- | --- |
| Age cohorts, income segmentation, provider mix, tenure by year, joins | Contacting individuals, geographic analysis, exact income, exact age, exact tenure |

**Would I release this?** No. 48.2% unique is not anonymity by any reading.
The extract is pseudonymous — `customer_id` still links it to source — so it
stays personal data and belongs under contract to a named recipient with
access control and purpose limitation. To release openly I would have to drop
`customer_id`, widen the income bands and coarsen birth year into ranges, and
I would want to re-measure rather than assume that gets there. k-anonymity is
in any case only a risk indicator: it says nothing about attribute disclosure
inside a group, and an attacker may hold attributes I did not model.

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

Measured against a held-out manifest of 3,670 planted defects: **100% recall,
96.8% attribution** (90.0% macro, weighting each defect class equally rather
than by volume). Recall alone would be a poor score — a pipeline that
quarantined every row would reach 100% — so it has to be read against the
73.7% retention figure, which that pipeline would drive to zero.

Two things the measurement caught that reading the output would not. Attribution
sits below recall because some planted values are legitimately reportable
under more than one check: `"N/A"` planted as a short address reads as
*missing* first. And duplicate detection was originally deriving its candidate
set from rows that had survived earlier checks, so 13 duplicates went unflagged
whenever their twin had already been quarantined for an unrelated reason — the
output was still unique, but only by accident. Deriving duplicates from the
whole input before any row is rejected took that defect from 72% to 100%
recall. The general lesson is that a check whose reach depends on what an
earlier stage happened to discard is not an invariant.

## 5. Production operations

5,000 rows in 0.7s, non-zero exit on failure, execution report written even
when a run dies. Every run asserts `rows_in == rows_out + rows_quarantined`.

**Retention is the gap I would close first.** The pipeline creates four copies
of every subject's personal data — raw, cleaned, quarantined, masked — and
deletes none. Article 5(1)(e) requires storage limitation and Article 17 a
right to erasure; neither is satisfiable, since there is no mechanism to find
a subject in the quarantine file, let alone remove them.

**Quarantine ownership is second.** 1,316 rows per run (26.3%) are set aside
with a reason. That is defensible engineering and an indefensible operating
model with nobody assigned. It needs a named steward, a remediation SLA and a
disposal rule — otherwise quarantine is a slower way of deleting data while
feeling responsible about it. 427 of those rows fail only on a blank optional
field; a tiered policy would lift retention from 73.7% to 82.2%.

Also open: no alerting threshold, so a run where quarantine jumps to 60%
succeeds quietly; and cleaning is a row-wise loop that will not hold at 10M
rows.

## 6. Lessons learned

**My test data hid my worst bug.** `clean_name()` stripped any character
outside `[A-Za-z '-]`, which silently turned `José` into `Jos` and `Nguyễn`
into `Nguyn` — and tagged the row `name_normalised`, reporting success. It
never surfaced because the generator uses `Faker("en_US")`, so no accented
name ever reached it. A pipeline built to protect people was corrupting the
names of everyone outside ASCII, and the fix is not a wider character class
but a change of principle: **repair only what is recoverable without guessing,
and reject the rest.** Deleting a character produces a plausible value that is
not the one the customer gave, and nothing downstream can tell it happened.
The same reasoning fixed `customer_id`, where `int(float(x))` was turning
`"12.9"` into `12`.

**Measuring the wrong scope is worse than not measuring.** The 1.2%
re-identification figure in §3 was precise, well-presented and wrong, because
it covered only the columns I had chosen to mask. A confident number computed
over a convenient subset is more dangerous than an admitted unknown, because
it stops anyone looking further.

**Config that declares a rule it does not run is worse than no config.**
`dob_before_created` sat in `rules.yml` for the life of the project and was
never executed — the file advertised a guarantee the pipeline did not provide.
Unknown check types now raise rather than being skipped.

**Quantifying a policy's cost changes how you see it.** 427 of 1,316
quarantined rows fail only on a blank optional field. Reporting that turned an
unexamined default into a decision someone can argue with. A validation rule
is a business choice wearing technical clothing.

The mistake I would most want to avoid repeating: I originally wrote raw phone
numbers and dates of birth into `data_quality_report.txt` as format examples,
and raw failing values — including dates of birth — into
`validation_results.txt`. A governance report that leaks the data it audits is
exactly the failure this project exists to catch, and I did it twice while
building the tool to prevent it. Handling rules apply to the artifacts, not
just the dataset.

## Governance controls recommended

| Risk identified | Control | GDPR basis |
| --- | --- | --- |
| Direct identifiers in free text (40 rows, 8 SSNs) | Content scanning on ingest, not schema-driven masking | Art. 32 |
| 48.2% of records unique on released attributes | Assess uniqueness over everything released; generalise until a k threshold is met | Recital 26 |
| `customer_id` links extract to source | Treat masked extract as personal data; release under contract | Recital 26 |
| Four copies, no deletion | Retention schedule and erasure across all artifacts | Art. 5(1)(e), Art. 17 |
| 1,316 quarantined rows, no owner | Named steward, remediation SLA, disposal rule | Art. 5(2) |
| Reports quoted raw PII | Redaction applied to artifacts as well as data | Art. 25 |
| Name corruption for non-ASCII scripts | Reject rather than repair where the value is not recoverable | Art. 5(1)(d) |
| No alerting on degradation | Quarantine-rate threshold; fail the run when exceeded | Art. 5(1)(d) |
