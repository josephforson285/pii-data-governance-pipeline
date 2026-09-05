# Reflection & Governance

> **STATUS: SCAFFOLD.** Every figure below is taken from the generated reports
> and is ready to cite. The blocks marked **Your analysis** are the graded
> part and are deliberately unwritten — the judgement calls are yours to make.
> Delete this block before submitting.

---

## 1. Top 5 data quality issues

Ranked by how much damage each would do downstream if it survived, not by row
count. Source: `data_quality_report.txt`, `cleaning_log.txt`.

| # | Issue | Scale | How it was fixed | Impact if it had survived |
| --- | --- | --- | --- | --- |
| 1 | Sentinel nulls (`"N/A"`, `"unknown"`, whitespace) | 442 values across 5 columns | Recognised as missing, not as text | Survives `dropna()`. Silently corrupts every mean, count and join |
| 2 | Non-standard phone formats | 8 distinct shapes, 1,026 rows | Digits extracted, reformatted `XXX-XXX-XXXX` | No reliable customer match or dedup; the same person looks like several |
| 3 | Non-standard / invalid dates | 8 shapes, 789 uncoercible | Multi-format parse, 750 repaired, 39 rejected | Age and tenure calculations wrong or crashing |
| 4 | Invalid `account_status` | 350 rows, 9 variants | Case/whitespace normalised, aliases mapped, 110 rejected | Segment counts wrong; `active` splits into 4 buckets |
| 5 | Duplicate `customer_id` | 47 ids, 50 surplus rows | Quarantined; uniqueness enforced at post-validation | Fan-out on every join; revenue double-counted |

**Your analysis** — which of these would have hurt most in a real fintech, and
why? (Consider: which are *visible* when they go wrong, and which fail
silently. #1 and #5 fail silently. That distinction is worth an argument.)

---

## 2. Risk assessment — sensitivity of detected PII

Source: `pii_detection_report.txt`.

- **8 of 10 columns carry personal data.** 5,000 of 5,000 records — there is no
  subset of this file that is safe to release unmasked.
- **40 rows leaked direct identifiers into the free-text `address` field:**
  18 phone numbers, 14 emails, **8 US SSNs**. Schema-driven masking finds none
  of these.
- **`customer_id` is PII.** It is a direct linkage key back to the unmasked
  source. Pseudonymised data is still personal data (GDPR Recital 26).
- Content scanning ran recall-first: 25,373 raw hits reduced to 18,876
  confirmed (74.4% precision) by declared suppression rules, not by narrowing
  the patterns.

**Your analysis** — rank the exposure. Which single finding would you escalate
first, and does this cross the GDPR Art. 33 threshold for notifying the
supervisory authority within 72 hours? (The SSNs are the strongest argument.
Say why.)

---

## 3. Masking trade-offs — utility vs privacy

Source: `masked_sample.txt`.

| Group size on quasi-identifiers | Before | After |
| --- | --- | --- |
| k=1 (uniquely identifiable) | 3,808 | 44 |
| k=2 | 0 | 126 |
| k=3–5 | 0 | 1,121 |
| k>5 | 0 | 2,517 |

**Uniquely re-identifiable: 100% → 1.2%.**

The critical point: that drop came from generalising **quasi-identifiers**
(dropping the postcode with the address, coarsening DOB to a year, banding
income). Masking names, emails and phones alone would have left it at 100%.

| Retained | Lost |
| --- | --- |
| Age analysis, income banding, provider mix, tenure, joins on `customer_id` | Contacting individuals, geographic analysis, exact income, exact age |

**Your analysis** — 44 records are still unique. Is that acceptable to release?
Argue both ways, then commit to one. (If you say yes: what compensating
control? If no: what generalisation would you add, and what analysis does that
cost the business?)

---

## 4. Validation strategy — was it effective

Source: `validation_results.txt`, `detection_scorecard.txt`.

- **3,510 rule failures across 2,633 rows → 0.** Every rule to zero.
- `lazy=True` is why a report exists at all — without it Pandera aborts on the
  first bad value.
- Rules live in `config/rules.yml`, so the policy can be re-argued without
  touching Python.
- Measured against the generator's manifest: **99.6% recall, 96.4%
  attribution.** The gap is classification ambiguity, not misses — `"N/A"`
  planted as a short address reads as *missing* before it reads as *short*.
- **One real finding:** 13 rows carrying a duplicate id reached the output
  without the dedup check firing, because the colliding row had already been
  quarantined for an unrelated reason. Output is still unique, but dedup recall
  depends on how much the previous stage happened to reject.

**Your analysis** — what does that dedup finding tell you about where
invariants belong? (The argument: a *scan* whose reach shifts with upstream
policy is not an invariant. Post-validation is.) What rule would you add that
the brief didn't specify?

---

## 5. Production operations

Current state: single-machine CLI, 5,000 rows in 0.80s, exit 1 on any stage
failure, execution report written even when a run dies.

Open questions this project has not answered:

- **Scheduling.** Batch or event-driven? What is the freshness requirement?
- **Failure handling.** 23.8% quarantine rate — does the run fail, or proceed
  and alert? What threshold?
- **The quarantine backlog.** 1,192 rows per run go somewhere. Who owns
  remediation, and what is the SLA before they are dropped for good?
- **Scale.** Cleaning is a row-wise Python loop. It will not hold at 10M rows.
- **Retention.** Nothing here deletes anything. GDPR Art. 5(1)(e) requires
  storage limitation, and Art. 17 gives a right to erasure — across raw,
  cleaned, quarantined *and* masked copies.

**Your analysis** — pick the two you would fix first and justify the order.
(The retention gap is arguably the biggest real risk: the pipeline currently
creates four copies of everyone's personal data and deletes none of them.)

---

## 6. Lessons learned

Prompts, not answers:

- The pre/post validation split — why does a single post-clean pass prove less
  than you would expect?
- 442 rows quarantined purely for a blank optional field. What did quantifying
  that change about how you think about a validation rule?
- Detection ran recall-first with suppressions on the record, rather than
  patterns tuned until output looked clean. Why does that ordering matter for
  a *security* control specifically?
- What would you do differently with the data model if you started again?

**Your analysis** — 3–5 sentences. Specific, not generic.

---

## Governance controls recommended

Maps to deliverable 4 of the module (GDPR scenario → controls).

| Risk found | Control | GDPR basis |
| --- | --- | --- |
| PII leaked into free text (40 rows) | Content scanning on ingest, not schema-driven masking | Art. 32 — security of processing |
| 100% unique on quasi-identifiers | Generalise quasi-identifiers before release; k-threshold | Recital 26 — anonymisation test |
| `customer_id` links back to source | Treat masked extract as personal data; access control it | Recital 26 — pseudonymisation |
| No retention or deletion | Retention schedule across all four copies | Art. 5(1)(e), Art. 17 |
| 1,192 quarantined rows, no owner | Named data steward, remediation SLA | Art. 5(2) — accountability |
| Reports quoted raw PII | Redaction in reporting (fixed in commit 6e1ac69) | Art. 25 — data protection by design |
