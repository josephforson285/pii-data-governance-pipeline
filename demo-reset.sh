#!/usr/bin/env bash
# Reset to a clean slate so the pipeline can be run from nothing.
#
#   ./demo-reset.sh          clear generated artifacts, leave the repo ready
#   ./demo-reset.sh --run    clear, then generate + run + score
#
# Everything it deletes regenerates from the seed. reports/reflection.md is
# written by hand and is never touched; the script aborts if that file has
# uncommitted changes.
#
# Checks the interpreter before deleting anything: a reset that clears the
# artifacts and then fails on a missing dependency is worse than no reset.
set -euo pipefail

cd "$(dirname "$0")"
export PYTHONPATH=src

# --- pick an interpreter --------------------------------------------------
# $PYTHON wins, then a local venv, then python3. A bare `python` is tried last
# because on many machines it points at whatever venv was created first.
pick_python() {
    local candidate
    for candidate in "${PYTHON:-}" .venv/bin/python venv/bin/python \
                     "$(command -v python3 || true)" "$(command -v python || true)"; do
        [ -n "$candidate" ] && [ -x "$candidate" ] || continue
        if "$candidate" -c 'import pandas, pandera, faker, yaml' 2>/dev/null; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

if ! INTERPRETER=$(pick_python); then
    echo "no usable interpreter found. nothing has been deleted."
    echo
    echo "the pipeline needs pandas, pandera, faker and PyYAML. either:"
    echo "  python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt"
    echo "or point the script at an environment that already has them:"
    echo "  PYTHON=/path/to/python ./demo-reset.sh"
    exit 1
fi

if ! "$INTERPRETER" -c 'import pipeline.cli' 2>/dev/null; then
    echo "interpreter works but 'pipeline' will not import. nothing has been deleted."
    echo "run this script from the repository root."
    exit 1
fi

# --- protect the one file nothing regenerates -----------------------------
if git rev-parse --git-dir >/dev/null 2>&1; then
    if [ -n "$(git status --porcelain reports/reflection.md)" ]; then
        echo "refusing to reset: reports/reflection.md has uncommitted changes."
        echo "commit or stash it first - nothing else here is unrecoverable."
        exit 1
    fi
else
    echo "warning: not a git repository, so reflection.md has no safety net."
    printf "continue? [y/N] "
    read -r reply
    [ "$reply" = "y" ] || { echo "aborted, nothing deleted."; exit 1; }
fi

echo "interpreter: $INTERPRETER"
echo "clearing generated artifacts..."
rm -f data/raw/customers_raw.csv data/raw/_ground_truth.json
rm -f data/processed/*.csv
rm -f data/rejects/*.csv
rm -f reports/*.txt reports/pipeline.log

echo
echo "state now:"
printf "  data/raw/          %s files\n" "$(find data/raw -type f ! -name .gitkeep | wc -l)"
printf "  data/processed/    %s files\n" "$(find data/processed -type f ! -name .gitkeep | wc -l)"
printf "  data/rejects/      %s files\n" "$(find data/rejects -type f ! -name .gitkeep | wc -l)"
printf "  reports/           %s generated (reflection.md kept)\n" \
       "$(find reports -name '*.txt' | wc -l)"

if [ "${1:-}" != "--run" ]; then
    echo
    echo "ready. next:"
    echo "  export PYTHONPATH=src"
    echo "  $INTERPRETER -m pipeline generate"
    echo "  $INTERPRETER -m pipeline run"
    echo "  $INTERPRETER -m pipeline score"
    exit 0
fi

for stage in generate run score; do
    echo
    echo "--- $stage $(printf '%.0s-' $(seq $((62 - ${#stage}))))"
    "$INTERPRETER" -m pipeline "$stage"
done

echo
echo "reports/ now holds:"
ls -1 reports/ | sed 's/^/  /'
