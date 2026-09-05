"""Generate a messy customer dataset with a recorded manifest of planted defects.

The manifest (`_ground_truth.json`) is held out: the pipeline never reads it.
Only `score.py` does, to measure detection recall.
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

import pandas as pd
from faker import Faker

COLUMNS = [
    "customer_id", "first_name", "last_name", "email", "phone",
    "date_of_birth", "address", "income", "account_status", "created_date",
]

STATUSES = ["active", "inactive", "suspended"]


@dataclass(frozen=True)
class Defect:
    """A single class of planted data quality problem."""
    name: str
    column: str
    rate: float
    apply: Callable[[list[dict], list[int], random.Random], None]


def _clean_rows(n: int, fake: Faker, rng: random.Random) -> list[dict]:
    today = date.today()
    rows = []
    for i in range(1, n + 1):
        first, last = fake.first_name(), fake.last_name()
        dob = fake.date_of_birth(minimum_age=18, maximum_age=88)
        created = today - timedelta(days=rng.randint(0, 2555))
        rows.append({
            "customer_id": i,
            "first_name": first,
            "last_name": last,
            "email": f"{first}.{last}@{fake.free_email_domain()}".lower(),
            "phone": f"{rng.randint(200,999)}-{rng.randint(200,999)}-{rng.randint(1000,9999)}",
            "date_of_birth": dob.isoformat(),
            "address": fake.address().replace("\n", ", "),
            "income": round(rng.uniform(18_000, 240_000), 2),
            "account_status": rng.choice(STATUSES),
            "created_date": created.isoformat(),
        })
    return rows


# --- injectors -------------------------------------------------------------
# Each mutates the given rows in place. Signature: (rows, targets, rng)

def _blank(col: str):
    def fn(rows, targets, rng):
        for i in targets:
            rows[i][col] = rng.choice(["", None, "   ", "NULL", "N/A"])
    return fn


def _phone_formats(rows, targets, rng):
    variants = [
        lambda a, b, c: f"({a}) {b}-{c}",
        lambda a, b, c: f"{a}.{b}.{c}",
        lambda a, b, c: f"{a}{b}{c}",
        lambda a, b, c: f"+1-{a}-{b}-{c}",
        lambda a, b, c: f"{a} {b} {c}",
        lambda a, b, c: f"1-{a}-{b}-{c}",
    ]
    for i in targets:
        a, b, c = rng.randint(200, 999), rng.randint(200, 999), rng.randint(1000, 9999)
        rows[i]["phone"] = rng.choice(variants)(a, b, c)


def _phone_unparseable(rows, targets, rng):
    for i in targets:
        rows[i]["phone"] = rng.choice(["555-CALL-NOW", "n/a", "12345", "phone pending", "+44 20 7946 0958"])


def _date_formats(col: str):
    def fn(rows, targets, rng):
        for i in targets:
            d = date.fromisoformat(rows[i][col]) if _is_iso(rows[i][col]) else date(1990, 1, 1)
            rows[i][col] = rng.choice([
                d.strftime("%m/%d/%Y"), d.strftime("%d-%m-%Y"),
                d.strftime("%B %d, %Y"), d.strftime("%Y/%m/%d"),
            ])
    return fn


def _date_invalid(col: str):
    def fn(rows, targets, rng):
        for i in targets:
            rows[i][col] = rng.choice(["invalid_date", "0000-00-00", "2026-02-30", "unknown"])
    return fn


def _negative_income(rows, targets, rng):
    for i in targets:
        rows[i]["income"] = -round(rng.uniform(500, 45_000), 2)


def _extreme_income(rows, targets, rng):
    for i in targets:
        rows[i]["income"] = round(rng.uniform(1.2e7, 9.9e8), 2)


def _income_as_text(rows, targets, rng):
    for i in targets:
        rows[i]["income"] = rng.choice(["$52,000", "75k", "not disclosed", "60,000.00"])


def _status_variants(rows, targets, rng):
    for i in targets:
        rows[i]["account_status"] = rng.choice(
            ["Active", "ACTIVE", "  active", "actv", "Inactive", "SUSPENDED", "closed", "pending", "1"]
        )


def _email_invalid(rows, targets, rng):
    for i in targets:
        first = str(rows[i]["first_name"]).lower()
        rows[i]["email"] = rng.choice([
            f"{first}@@corp.com", f"{first}.corp.com", f"{first}@corp",
            "@nodomain.com", f"{first} @corp.com", "not an email",
        ])


def _name_dirty(col: str):
    def fn(rows, targets, rng):
        for i in targets:
            v = str(rows[i][col])
            rows[i][col] = rng.choice([v.lower(), v.upper(), f"  {v}  ", f"{v}3", "X", f"{v}123"])
    return fn


def _address_short(rows, targets, rng):
    for i in targets:
        rows[i]["address"] = rng.choice(["N/A", "unknown", "PO Box", "-", "n/a"])


def _pii_in_address(rows, targets, rng):
    """PII leaking into a free-text field - only a content scan finds this."""
    for i in targets:
        base = str(rows[i]["address"])
        leak = rng.choice([
            f"contact {rows[i]['first_name']}.{rows[i]['last_name']}@gmail.com".lower(),
            f"tel {rng.randint(200,999)}-{rng.randint(200,999)}-{rng.randint(1000,9999)}",
            f"SSN {rng.randint(100,899)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}",
        ])
        rows[i]["address"] = f"{base}, {leak}"


def _impossible_age(rows, targets, rng):
    for i in targets:
        rows[i]["date_of_birth"] = date(rng.randint(1800, 1870), rng.randint(1, 12), rng.randint(1, 28)).isoformat()


def _future_created(rows, targets, rng):
    for i in targets:
        rows[i]["created_date"] = (date.today() + timedelta(days=rng.randint(30, 900))).isoformat()


def _is_iso(v) -> bool:
    try:
        date.fromisoformat(str(v))
        return True
    except ValueError:
        return False


DEFECTS: list[Defect] = [
    Defect("missing_email", "email", 0.020, _blank("email")),
    Defect("missing_phone", "phone", 0.030, _blank("phone")),
    Defect("missing_income", "income", 0.045, _blank("income")),
    Defect("missing_address", "address", 0.015, _blank("address")),
    Defect("missing_dob", "date_of_birth", 0.012, _blank("date_of_birth")),
    Defect("phone_nonstandard_format", "phone", 0.180, _phone_formats),
    Defect("phone_unparseable", "phone", 0.008, _phone_unparseable),
    Defect("dob_nonstandard_format", "date_of_birth", 0.090, _date_formats("date_of_birth")),
    Defect("dob_invalid_value", "date_of_birth", 0.010, _date_invalid("date_of_birth")),
    Defect("created_date_nonstandard_format", "created_date", 0.060, _date_formats("created_date")),
    Defect("created_date_future", "created_date", 0.006, _future_created),
    Defect("income_negative", "income", 0.014, _negative_income),
    Defect("income_above_cap", "income", 0.005, _extreme_income),
    Defect("income_non_numeric", "income", 0.010, _income_as_text),
    Defect("status_invalid", "account_status", 0.070, _status_variants),
    Defect("email_malformed", "email", 0.035, _email_invalid),
    Defect("first_name_dirty", "first_name", 0.050, _name_dirty("first_name")),
    Defect("last_name_dirty", "last_name", 0.040, _name_dirty("last_name")),
    Defect("address_too_short", "address", 0.012, _address_short),
    Defect("pii_leaked_in_address", "address", 0.008, _pii_in_address),
    Defect("age_impossible", "date_of_birth", 0.004, _impossible_age),
]

DUPLICATE_ID_RATE = 0.010


def generate(n_rows: int = 5000, seed: int = 42) -> tuple[pd.DataFrame, dict]:
    rng = random.Random(seed)
    fake = Faker("en_US")
    Faker.seed(seed)

    rows = _clean_rows(n_rows, fake, rng)

    # Reserve targets per column so two defects never overwrite each other.
    taken: dict[str, set[int]] = defaultdict(set)
    manifest: dict[str, dict] = {}

    for d in DEFECTS:
        pool = [i for i in range(n_rows) if i not in taken[d.column]]
        k = min(int(round(n_rows * d.rate)), len(pool))
        targets = sorted(rng.sample(pool, k))
        d.apply(rows, targets, rng)
        taken[d.column].update(targets)
        manifest[d.name] = {"column": d.column, "count": k, "rows": targets}

    # Duplicate IDs last: copies an existing id onto a later row.
    dup_targets = sorted(rng.sample(range(1, n_rows), int(round(n_rows * DUPLICATE_ID_RATE))))
    for i in dup_targets:
        rows[i]["customer_id"] = rows[rng.randrange(0, i)]["customer_id"]
    manifest["duplicate_customer_id"] = {
        "column": "customer_id", "count": len(dup_targets), "rows": dup_targets,
    }

    df = pd.DataFrame(rows, columns=COLUMNS)
    ground_truth = {
        "seed": seed,
        "n_rows": n_rows,
        "total_defects": sum(v["count"] for v in manifest.values()),
        "defects": manifest,
    }
    return df, ground_truth


def write(out_dir: Path, n_rows: int = 5000, seed: int = 42) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    df, truth = generate(n_rows, seed)
    csv_path = out_dir / "customers_raw.csv"
    df.to_csv(csv_path, index=False)
    (out_dir / "_ground_truth.json").write_text(json.dumps(truth, indent=2))
    return csv_path
