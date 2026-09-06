# Reflection & Governance

PII Detection & Data Quality Validation Pipeline — 5,000 synthetic customer
records. Figures cite the reports in this directory.

## 1. Top five data quality issues

| Issue | Scale | Fix | Impact if unfixed |
| --- | --- | --- | --- |
| Sentinel nulls (`"N/A"`, whitespace) | 418 values, 5 columns | Counted as missing at profiling | Survives `dropna()`; corrupts every mean and join |
| Non-standard phone formats | 8 shapes, 1,036 rows | Reformatted; 34 quarantined | One customer looks like several; dedup fails |
| Unparseable / non-standard dates | 787 values | 748 repaired, 39 quarantined | Age and tenure wrong or crashing |
| Invalid `account_status` | 350 rows, 9 variants | Case/alias mapping; 110 quarantined | `active` splits into 4 buckets |
| Duplicate `customer_id` | 47 ids, 50 surplus rows | Detected across whole input; quarantined | Joins fan out; balances double-counted |

`income` shows why the first matters: 93 true nulls and 142 sentinels.
`dropna()` removes the 93 and leaves the 142 poisoning every downstream
statistic. Issues 1, 3 and 5 fail *silently* — they produce plausible numbers
that are wrong, which makes them more expensive than the visible ones.

## 2. Risk assessment

Eight of ten columns carry personal data; all 5,000 records contain a name, an
identifier and contact details. No subset is safe unmasked.

I would escalate first the **eight US SSNs inside the free-text `address`
field**, alongside 18 phones and 14 emails — 40 rows. An SSN enables identity
theft directly; the column was never meant to hold identifiers, so no
schema-driven control would have caught them; and their presence implies the
source system accepts unvalidated free text into a field treated as
low-sensitivity downstream.

They surfaced only because the scan runs every pattern against every column.
That cost specificity — 25,365 raw matches reduced to 18,876, a **74.4%
confirmation rate** — and the discards are in the report with a written reason
rather than the patterns being narrowed until output looked clean. For a
security control that trade is right: a false positive costs review time, a
missed identifier is a breach.

`customer_id` is personal data too: an integer that reads as harmless but is a
direct linkage key (Recital 26). On Article 33, every factor an assessment
would weigh is present; the determination is formal risk assessment, not
something the pipeline makes, but I would expect it to clear.

## 3. Masking trade-offs

Before masking, **100% of 3,682 cleaned records were uniquely identifiable on
quasi-identifiers alone**. After, 1,761 remain unique: **47.8%**.

That figure was originally 1.2%, and it was wrong. I computed it over the
*masked* columns only, ignoring `created_date` — released untouched because I
had classified it operational non-PII, and carrying 1,957 distinct values
across 3,684 rows. Including it, masking took uniqueness from 100% to
**99.7%**: the controls achieved almost nothing while the report claimed a
99-point win. Generalising it to year gives the real 47.8%.

**A privacy metric computed over a subset of what you release is not a privacy
metric.** It must cover every attribute that leaves the building, including
the ones you decided were boring.

Retained: age cohorts, income bands, provider mix, tenure by year, joins.
Lost: contacting individuals, geographic analysis, exact income and age.

**Would I release it?** No. 47.8% is not anonymity, and `customer_id` still
links to source — so it stays personal data, under contract to a named
recipient with access control. Open release would need `customer_id` dropped,
wider bands, birth year in ranges, then re-measuring. k-anonymity is a risk
indicator, not proof: it ignores attribute disclosure within a group, and an
attacker may hold attributes I did not model.

## 4. Validation strategy

Rules live in `config/rules.yml`, so policy changes without touching code.
Validation runs both sides of cleaning: **3,527 failures across 2,658 rows to
zero**. `lazy=True` is what makes a report possible rather than a traceback.
Separating uncoercible from absent values mattered: 489 dates were present and
unparseable, 71 blank — different fixes, and the 489 matched the profiler's
independent count.

Against 3,670 planted defects: **100% recall, 97.0% attribution** (90.7%
macro). Recall alone is a poor score — quarantining everything scores 100% —
so the harness measures **specificity** too: of 2,261 rows with nothing
planted, none were quarantined. A test asserts a quarantine-everything
pipeline scores 100% recall and 0% specificity.

Two findings measurement produced that reading output would not. Duplicate
detection originally drew candidates from rows surviving earlier checks, so 13
duplicates went unflagged when their twin was already quarantined — unique by
accident, now 100%. And **pre-mask containment is 99.2%**: 30 rows with PII leaked into
free text reach `customers_cleaned.csv` untouched, since cleaning only
normalises address whitespace. Address suppression removes them at masking,
and a `verify_release` stage re-scans the extract to confirm it.

A check whose reach depends on what an earlier stage discarded is not an
invariant.

## 5. Production operations

5,000 rows in 1.5s, non-zero exit on failure, execution report written even
when a run dies. Every run asserts `rows_in == rows_out + rows_quarantined`,
and post-clean validation **gates publication** — the extract is written only
once it satisfies the schema it claims to.

**Retention is the first gap.** Four copies of every subject's personal data —
raw, cleaned, quarantined, masked — and none deleted. Art. 5(1)(e) requires
storage limitation and Art. 17 a right to erasure; neither is satisfiable,
since there is no way to find a subject in the quarantine file.

**Quarantine ownership is second.** 1,318 rows per run (26.4%) set aside with
a reason is defensible engineering and an indefensible operating model with
nobody assigned. 418 fail only on a blank optional field; a tiered policy
lifts retention from 73.6% to 82.0%. Also open: no alerting threshold, and a
row-wise loop that will not hold at 10M rows.

## 6. Lessons learned

**My test data hid my worst bug.** `clean_name()` stripped anything outside
`[A-Za-z '-]`, silently turning `José` into `Jos` and `Nguyễn` into `Nguyn` —
and tagged the row `name_normalised`, reporting success. It never surfaced
because the generator uses `Faker("en_US")`. The fix is a principle, not a
wider character class: **repair only what is recoverable without guessing.**
Deleting a character produces a plausible value that is not the customer's,
and nothing downstream can tell. Same reasoning fixed `customer_id`, where
`int(float(x))` turned `"12.9"` into `12`.

**A control that is not verified is an assumption.** I added a stage to
re-scan the masked extract, then found it only scanned columns the policy
claimed to mask — so deleting a masking rule deleted the check with it. It
could not catch the failure it existed for.

**Config declaring a rule it does not run is worse than no config.**
`dob_before_created` sat in `rules.yml` and never executed.

The mistake I would least want to repeat: I wrote raw phone numbers and dates
of birth into two reports as examples. A governance report that leaks the data
it audits is exactly the failure this project exists to catch — and I did it
twice while building the tool to prevent it.

## Governance controls recommended

| Risk identified | Control | GDPR basis |
| --- | --- | --- |
| Direct identifiers in free text (40 rows, 8 SSNs) | Content scanning on ingest, not schema-driven masking | Art. 32 |
| 47.8% unique on released attributes | Assess uniqueness over everything released; generalise to a k threshold | Recital 26 |
| `customer_id` links extract to source | Treat masked extract as personal data; release under contract | Recital 26 |
| Four copies, no deletion | Retention schedule and erasure across all artifacts | Art. 5(1)(e), Art. 17 |
| 1,318 quarantined rows, no owner | Named steward, remediation SLA, disposal rule | Art. 5(2) |
| Reports quoted raw PII | Redaction applied to artifacts as well as data | Art. 25 |
| Non-ASCII name corruption | Reject rather than repair where value is not recoverable | Art. 5(1)(d) |
| Masking assumed, not verified | Re-scan released extract; fail on residual identifiers | Art. 25 |
