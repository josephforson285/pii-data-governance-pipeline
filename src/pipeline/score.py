"""Measure detection against the generator's manifest of planted defects.

Nothing under run() reads the ground truth: a detector that can see the answer
key measures nothing. Recall is not a quality score on its own - quarantining
every row scores 100% - so it is paired with specificity.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Score:
    defect: str
    column: str
    planted: int
    handled: int
    attributed: int
    escaped: int = 0

    @property
    def recall(self) -> float:
        """Was the defect acted on at all - repaired or rejected."""
        return self.handled / self.planted if self.planted else 1.0

    @property
    def attribution(self) -> float:
        """Was it caught by the check that should have caught it."""
        return self.attributed / self.planted if self.planted else 1.0

    @property
    def pre_mask_containment(self) -> float:
        """Share of planted defects that did not survive into the cleaned
        extract. Masking may still remove what does survive - this measures
        cleaning, not the final release."""
        return 1 - (self.escaped / self.planted) if self.planted else 1.0


@dataclass
class ScoreCard:
    scores: list[Score]
    unmeasured: list[str]
    clean_rows: int = 0
    falsely_quarantined: int = 0

    @property
    def escaped(self) -> int:
        return sum(s.escaped for s in self.scores)

    @property
    def pre_mask_containment(self) -> float:
        return 1 - (self.escaped / self.planted) if self.planted else 1.0

    @property
    def specificity(self) -> float:
        """Share of defect-free rows that were not quarantined.

        The counterweight to recall: quarantining everything scores perfect
        recall and zero specificity, so the pair cannot both be gamed.
        """
        if not self.clean_rows:
            return 1.0
        return 1 - self.falsely_quarantined / self.clean_rows

    @property
    def planted(self) -> int:
        return sum(s.planted for s in self.scores)

    @property
    def handled(self) -> int:
        return sum(s.handled for s in self.scores)

    @property
    def attributed(self) -> int:
        return sum(s.attributed for s in self.scores)

    @property
    def recall(self) -> float:
        """Micro: weighted by planted volume, so frequent defects dominate."""
        return self.handled / self.planted if self.planted else 1.0

    @property
    def attribution(self) -> float:
        return self.attributed / self.planted if self.planted else 1.0

    @property
    def macro_recall(self) -> float:
        """Each defect class weighted equally, so a rare broken rule shows."""
        return sum(s.recall for s in self.scores) / len(self.scores) if self.scores else 1.0

    @property
    def macro_attribution(self) -> float:
        return (sum(s.attribution for s in self.scores) / len(self.scores)
                if self.scores else 1.0)


# Which check each planted defect is expected to be caught by. Attribution
# measures whether that specific check fired; recall measures only whether the
# row was acted on at all. The two diverge where a planted value is ambiguous -
# 'N/A' planted as a short address reads as missing, which is a defensible
# classification, so recall stays 100% while attribution does not.
DEFECT_TO_CHECK = {
    "income_negative": ("rejection", "income_out_of_range"),
    "income_above_cap": ("rejection", "income_out_of_range"),
    "income_non_numeric": ("rejection", "unparseable_income"),
    "phone_unparseable": ("rejection", "unparseable_phone"),
    "dob_invalid_value": ("rejection", "unparseable_date"),
    "age_impossible": ("rejection", "implausible_age"),
    "created_date_future": ("rejection", "future_created_date"),
    "email_malformed": ("rejection", "malformed_email"),
    "address_too_short": ("rejection", "address_too_short"),
    "duplicate_customer_id": ("rejection", "duplicate_customer_id"),
    "pii_leaked_in_address": ("pii_leak", "address"),
    "missing_email": ("rejection", "missing_required_field"),
    "missing_phone": ("rejection", "missing_required_field"),
    "missing_income": ("rejection", "missing_required_field"),
    "missing_address": ("rejection", "missing_required_field"),
    "missing_dob": ("rejection", "missing_required_field"),
    "phone_nonstandard_format": ("repair", "phone_normalised"),
    "dob_nonstandard_format": ("repair", "date_normalised"),
    "created_date_nonstandard_format": ("repair", "date_normalised"),
    "status_invalid": ("mixed", "status"),
    "first_name_dirty": ("mixed", "first_name"),
    "last_name_dirty": ("mixed", "last_name"),
}

# "mixed" defects plant several kinds of damage in one column, so no single
# check owns them and attribution equals recall by construction.


def load_ground_truth(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def score(truth: dict, clean_log, pii_report) -> ScoreCard:
    """Compare planted rows against what each stage actually acted on."""
    rejected_by_reason: dict[str, set[int]] = {}
    for r in clean_log.rejections:
        rejected_by_reason.setdefault(r.reason, set()).add(r.row)
    repaired_by_tag: dict[str, set[int]] = {}
    for r in clean_log.repaired:
        repaired_by_tag.setdefault(r.tag, set()).add(r.row)

    leak_rows: set[int] = set()
    for f in pii_report.leaks:
        leak_rows.update(f.rows)

    # The scorer observes cleaning only, not the publication gate.
    rejected_rows = {r.row for r in clean_log.rejections}
    survived_cleaning = set(range(truth["n_rows"])) - rejected_rows
    repaired_rows_by_column: dict[str, set[int]] = {}
    for r in clean_log.repaired:
        repaired_rows_by_column.setdefault(r.column, set()).add(r.row)

    scores, unmeasured = [], []
    for defect, info in truth["defects"].items():
        planted = set(info["rows"])
        column = info["column"]
        mapping = DEFECT_TO_CHECK.get(defect)
        if mapping is None:
            unmeasured.append(defect)
            continue
        kind, key = mapping

        # Handled: the pipeline acted on this row for this column at all.
        if kind == "pii_leak":
            handled = planted & leak_rows
            attributed = handled
        else:
            handled = planted & clean_log.touched_rows(column)
            if kind == "rejection":
                attributed = planted & rejected_by_reason.get(key, set())
            elif kind == "repair":
                attributed = planted & repaired_by_tag.get(key, set())
            else:
                attributed = handled

        # Survived cleaning untouched in its own column. Masking may still
        # remove it; recall alone would not say it survived.
        escaped = ((planted & survived_cleaning)
                   - repaired_rows_by_column.get(column, set()))
        scores.append(Score(defect, column, len(planted), len(handled),
                            len(attributed), len(escaped)))

    # Defect-free rows quarantined anyway: the counterweight to recall.
    planted_anywhere: set[int] = set()
    for info in truth["defects"].values():
        planted_anywhere.update(info["rows"])
    all_rows = set(range(truth["n_rows"]))
    clean_rows = all_rows - planted_anywhere
    quarantined = {r.row for r in clean_log.rejections}

    return ScoreCard(
        scores=sorted(scores, key=lambda s: (s.recall, s.attribution)),
        unmeasured=unmeasured,
        clean_rows=len(clean_rows),
        falsely_quarantined=len(clean_rows & quarantined),
    )
