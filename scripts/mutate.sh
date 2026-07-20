#!/usr/bin/env bash
# Mutation harness for the C1 device management invariants.
#
# Three outcomes, never two:
#   CAUGHT       - the mutant compiles AND a test fails
#   SURVIVED     - the mutant compiles AND every test passes
#   INCONCLUSIVE - the mutant does not compile, so the test run proves nothing
#
# The compile gate is the point. `go test` exits non-zero for a build failure
# exactly as it does for a failing assertion, so a harness that only checked the
# exit code would score every typo as a catch.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

FILE="$1"; FROM="$2"; TO="$3"; PKG="${4:-./...}"; NAME="${5:-$FILE}"

BACKUP="$(mktemp)"
cp "$FILE" "$BACKUP"
restore() { cp "$BACKUP" "$FILE"; rm -f "$BACKUP"; }
trap restore EXIT

if ! grep -qF -- "$FROM" "$FILE"; then
  echo "INCONCLUSIVE  $NAME (pattern not found; the harness never mutated anything)"
  exit 3
fi
python3 - "$FILE" "$FROM" "$TO" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if s.count(old) != 1:
    sys.exit("pattern appears %d times; expected exactly 1" % s.count(old))
open(path, "w").write(s.replace(old, new))
PY
if [ $? -ne 0 ]; then
  echo "INCONCLUSIVE  $NAME (ambiguous pattern)"
  exit 3
fi

# Gate 1: does the mutant compile? `go vet` builds the package and its tests.
if ! go vet "$PKG" >/tmp/mutate_build.log 2>&1; then
  echo "INCONCLUSIVE  $NAME (mutant does not compile; a test run would prove nothing)"
  sed -n '1,5p' /tmp/mutate_build.log
  exit 3
fi

# Gate 2: the mutant compiles, so the test result is now meaningful.
if go test "$PKG" -count=1 >/tmp/mutate_test.log 2>&1; then
  echo "SURVIVED      $NAME  <-- no test detected this change"
  exit 1
fi

echo "CAUGHT        $NAME"
grep -E '^\s+--- FAIL|^--- FAIL|\.go:[0-9]+:' /tmp/mutate_test.log | head -4
exit 0
