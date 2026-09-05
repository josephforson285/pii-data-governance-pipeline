# Reflection & Governance

PII Detection & Data Quality Validation Pipeline — 5,000 synthetic customer
records. All figures cite the generated reports in this directory.

---

## 1. Top five data quality issues

I ranked these by consequence rather than by row count, because the largest
problems in this dataset were not the loudest ones.

**1. Sentinel nulls — 442 values across five columns.**
Found by counting `"N/A"`, `"NULL"`, `"unknown"`, `"-"` and whitespace-only
strings separately from true nulls in `data_quality_report.txt`. The `income`
column has 83 real nulls and 156 sentinels; a completeness check that reports
only `isna()` understates missingness on that column by nearly two thirds.
Fixed by treating them as missing at the profiling stage, before any cleaning.
The impact of missing this is that `dropna()` removes the 83 and leaves the
156 in place, where they are silently counted as valid strings by every mean,
group-by and join downstream. This is the worst issue in the dataset precisely
because nothing fails when it goes wrong.

**2. Non-standard phone formats — eight distinct shapes over 1,026 rows.**
The format inventory in `data_quality_report.txt` collapses each value to a
shape (digits to `9`) and counts the distinct ones: `(999) 999-9999`,
`999.999.9999`, `+9-999-999-9999` and five others. Fixed by extracting digits,
stripping a leading country code and reformatting to `XXX-XXX-XXXX`; 900 rows
repaired, 34 unparseable rows quarantined. Left alone, the same customer
appears as several distinct people to any matching or deduplication process,
which corrupts customer counts and defeats contact suppression lists.

**3. Unparseable and non-standard dates — 789 values.**
489 in `date_of_birth` and 300 in `created_date` would not convert to a date.
The validator counts these separately from absent values, because
`"May 24, 1940"` needs a parser while a blank field needs a decision. 750 were
repaired by trying five formats in order; 39 were genuinely invalid
(`"invalid_date"`, `"2026-02-30"`) and quarantined. Unfixed, age and tenure
calculations either crash or silently produce nulls that are then treated as
zero.

**4. Invalid `account_status` — 350 rows across nine variants.**
`"Active"`, `"ACTIVE"`, `"  active"`, `"actv"`, `"closed"`, `"pending"`, `"1"`
and others. 240 were repaired by normalising case and whitespace or mapping a
declared alias; 110 had no defensible mapping and were quarantined —
`"closed"` is not one of the three permitted states and guessing which it
means would be inventing data. Unfixed, a single `active` segment fragments
into four buckets and every status-based report is wrong by roughly 7%.

**5. Duplicate `customer_id` — 47 distinct ids over 50 surplus rows.**
Reported as two numbers deliberately: uniqueness is a yes/no, but the blast
radius needs the row count, and some ids appear three and four times. Fixed by
quarantining duplicates and enforcing uniqueness at post-validation. Unfixed,
every join on `customer_id` fans out, and in a fintech context that means
transactions and balances double-counted against a single customer.

The common thread across 1, 3 and 5 is that they fail silently. A malformed
email is visible the moment someone tries to send to it. A sentinel null and a
duplicated key both produce plausible-looking numbers that are wrong, which is
a far more expensive failure mode.

---

## 2. Risk assessment — sensitivity of the detected PII

Eight of ten columns carry personal data, and all 5,000 records contain a
name, an identifier and contact details. There is no subset of this file that
is safe to release unmasked.

The finding I would escalate first is **eight US Social Security Numbers found
inside the free-text `address` field**, alongside 18 phone numbers and 14
email addresses — 40 rows in total. These matter more than their volume
suggests for three reasons. An SSN is a national identifier that enables
identity theft directly, so its sensitivity is categorically higher than a
name or an email. They are in a column that is not supposed to hold
identifiers at all, so no schema-driven control was ever going to catch them —
masking the `email` column finds none of them. And their presence means the
upstream system is accepting unvalidated free text into a field that is then
treated as low-sensitivity downstream, which implies there are probably more
of them in data this project has not seen.

I found these only because the scan runs every pattern against every column
rather than trusting column names. That decision cost precision — 25,373 raw
matches reduced to 18,876 confirmed, 74.4% — and I kept the discarded matches
in the report with a written reason each rather than narrowing the patterns
until the output looked clean. For a security control that trade is the right
way round: a false positive costs review time, a missed identifier is a
breach.

I would also record that `customer_id` is personal data. It is an integer, so
it reads as harmless, but it is a direct linkage key back to the unmasked
source. Under GDPR Recital 26 pseudonymised data remains personal data, and
keeping that key in the shared extract is what makes the extract
pseudonymous rather than anonymous.

**On the Article 33 threshold:** if this file were disclosed I would notify the
supervisory authority within 72 hours. The test is whether the breach is
likely to result in a risk to the rights and freedoms of data subjects. 5,000
complete identity records, each with home address and exact income, and eight
with an SSN, clears that bar comfortably. The financial data alone makes
targeted fraud plausible; the SSNs make identity theft plausible. I would not
treat this as a case where the risk assessment is genuinely arguable.

---

## 3. Masking trade-offs — utility versus privacy

The masking rules mask names to an initial, emails to a first character plus
domain, phones to the last four digits, dates of birth to the year, and
replace the address entirely.

The result that changed how I think about masking is in `masked_sample.txt`.
Before masking, **3,808 of 3,808 cleaned records — 100% — were uniquely
identifiable on quasi-identifiers alone**: birth year, postal code and exact
income, none of which is a direct identifier. After masking, 44 records
remain unique, or 1.2%.

That drop did not come from masking the names, emails and phones. It came from
generalising the quasi-identifiers: the postal code disappeared when the
address was replaced, the birth date was coarsened to a year, and income was
banded into £25,000 ranges. Had I implemented only the five rules the brief
lists, every one of the 3,808 records would still have been uniquely
identifiable to anyone holding a second dataset with those same three
attributes. The masked file would have looked thoroughly protected and would
have offered no protection at all against a linkage attack.

Two rules I added for that reason. **Address is replaced wholesale rather than
partially** — keeping a city or postal code would have been more useful
analytically, but the address is free text and part 2 proved it contains
leaked emails, phones and SSNs, so anything short of full replacement leaves
them in place. **Income is banded rather than kept exact**, which costs precise
financial statistics but breaks the uniqueness that exact values create.

What survives: age analysis, income segmentation by band, email provider mix,
account status and tenure reporting, and joins on `customer_id`. What is gone:
contacting individuals, any geographic analysis, exact income figures, and
exact age or birthday.

**On whether I would release the 44:** no, not as an open extract. The
honest reading is that 1.2% unique is a large improvement and still not
anonymity, and the file remains personal data under Recital 26 because
`customer_id` links it back to source. I would release it under contract to a
named recipient with access controls and a purpose limitation, which is a
governance answer rather than a technical one. If it genuinely had to go out
unrestricted, I would suppress those 44 records or widen the income bands
until they fall into groups — accepting the loss of analytic resolution, since
a control that protects 98.8% of people and silently exposes the rest is not a
control I would want to defend afterwards.

---

## 4. Validation strategy — was it effective

Rules are declared in `config/rules.yml` and translated into pandera checks, so
the policy can be changed and argued about without touching pipeline code.
Validation runs twice, before and after cleaning. **3,510 rule failures across
2,633 rows went to zero**, and that delta is the actual evidence of
remediation; a single post-clean pass would only have proved that the clean
data is clean, which is true by construction and worth nothing.

Two things made the reporting usable. `lazy=True`, without which pandera
aborts on the first bad value and produces a traceback rather than a report.
And counting uncoercible values separately from absent ones: both look like
nulls to pandera after coercion, but 489 `date_of_birth` values were present
and unparseable while 71 were genuinely blank, and those need different fixes.
That 489 matched the profiler's independent count of unparseable dates
exactly, which is the kind of agreement between two separate code paths that
makes me trust both.

Because the dataset is generated, I could measure the rules instead of
asserting they work. Against a held-out manifest of 3,670 planted defects the
pipeline scored **99.6% recall and 96.4% attribution** — recall meaning the
row was acted on, attribution meaning the check I expected to catch it is the
one that fired. My first version reported only the second number and showed
`income_non_numeric` at 0%, which looked like a broken detector. It was not:
`"$52,000"` and `"75k"` are repaired, so the "unparseable income" check
correctly never fires. Splitting the metric turned an apparent failure into a
measurement.

The one genuine finding was in deduplication. **Thirteen rows carrying a
duplicate `customer_id` reached the output without the dedup check firing**,
yet the cleaned file contains zero duplicates — because the other row holding
each of those ids had already been quarantined for an unrelated reason, so no
collision existed to detect. The output is correct, but the property is
fragile: the reach of that scan depends on how much the previous stage
happened to reject. Relax the nullability policy, as section 4 of
`cleaning_log.txt` describes, and those thirteen pairs collide for real. The
lesson is that a scan whose coverage moves with upstream policy is not an
invariant. Uniqueness has to be enforced at the output, which post-validation
does, and not inferred from a check that only fires when two rows happen to
meet.

If I added one rule the brief does not specify, it would be a cross-field
check that `date_of_birth` precedes `created_date`. Every rule here validates
a column in isolation, and a customer created before they were born would pass
all of them.

---

## 5. Production operations

The pipeline is a single-machine CLI that processes 5,000 rows in 0.80
seconds, exits non-zero on any stage failure, and writes its execution report
even when a run dies — the case where that report is most needed. Every run
asserts `rows_in == rows_out + rows_quarantined` and aborts on a mismatch, so
a row lost to a swallowed exception cannot be mistaken for a row that was
never there.

Several things would have to be settled before this ran unattended.

**Retention is the gap I would close first.** The pipeline creates four copies
of every data subject's personal data — raw, cleaned, quarantined and masked —
and deletes none of them. GDPR Article 5(1)(e) requires storage limitation and
Article 17 gives a right to erasure, and neither is satisfiable today: an
erasure request would have to be honoured across all four artifacts and there
is no mechanism to find a subject in the quarantine file, let alone remove
them. This is the largest real-world risk in the project, and it is a gap the
brief does not ask about, which is part of why it is easy to miss.

**Ownership of the quarantine backlog is second.** 1,192 rows per run —
23.8% — are set aside with a reason. That is defensible as engineering and
indefensible as an operating model with nobody assigned to it. It needs a
named data steward, a remediation SLA and a rule for what happens to rows that
are never fixed. Without that, quarantine is just a slower way of deleting
data while feeling responsible about it.

Beyond those: scheduling and freshness requirements are undefined; there is no
alerting threshold, so a run where the quarantine rate jumps from 24% to 60%
currently succeeds quietly; and cleaning is a row-wise Python loop that will
not hold at ten million rows and would need vectorising or moving to Spark.

---

## 6. Lessons learned

The most useful decision I made was to generate the dataset with a held-out
manifest of planted defects, which let me measure detection instead of
assuming it. That is where the deduplication finding came from, and I would
not have found it by reading the output.

The second was to load the CSV as text. Letting pandas infer types would have
quietly repaired the exact defects the profiler exists to find — a negative
income becomes a valid float, `invalid_date` becomes `NaT` and is
indistinguishable from a blank. Profiling means seeing the file as it is;
coercion belongs after the damage has been recorded.

Quantifying the cost of a policy changed how I think about validation rules.
Retention is 76.2%, and 442 of the 1,192 quarantined rows fail only because an
optional field was blank — a tiered policy would retain 85%. I kept the strict
rule because the brief declares those fields mandatory, but reporting the
number turned an unexamined default into a decision someone can argue with. A
validation rule is a business choice wearing technical clothing, and it should
be as visible as one.

The mistake worth recording is that I originally wrote raw phone numbers and
dates of birth into `data_quality_report.txt` as format examples. The data is
synthetic so nothing was disclosed, but a governance report that leaks the
data it is auditing is precisely the failure this project exists to catch, and
I did it while building the tool to prevent it. Handling rules have to apply
to the artifacts as much as to the dataset.

---

## Governance controls recommended

| Risk identified | Control | GDPR basis |
| --- | --- | --- |
| Direct identifiers in free text (40 rows, 8 SSNs) | Content scanning on ingest; do not rely on schema-driven masking | Art. 32 — security of processing |
| 100% of records unique on quasi-identifiers | Generalise quasi-identifiers before release; test against a k threshold | Recital 26 — anonymisation test |
| `customer_id` links the extract back to source | Treat the masked extract as personal data; release under contract with access control | Recital 26 — pseudonymisation |
| Four copies of personal data, no deletion | Retention schedule and erasure mechanism covering raw, cleaned, quarantined and masked | Art. 5(1)(e), Art. 17 |
| 1,192 quarantined rows with no owner | Named data steward, remediation SLA, disposal rule | Art. 5(2) — accountability |
| Reports quoted raw PII | Redaction in reporting, applied to artifacts as well as data | Art. 25 — data protection by design |
| No alerting on quality degradation | Threshold on quarantine rate; fail the run when exceeded | Art. 5(1)(d) — accuracy |
