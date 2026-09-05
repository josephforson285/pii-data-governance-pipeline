"""Shared dataset loading."""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_raw(path: Path) -> pd.DataFrame:
    """Load every column as text.

    Pandas would otherwise coerce or drop malformed values on read - a negative
    income becomes a valid float, 'invalid_date' becomes NaT - and the defects
    the profiler exists to find would be gone before it ran.
    """
    return pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""])
