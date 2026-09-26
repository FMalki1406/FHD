#!/usr/bin/env bash
#
# Runs one test by exact name and fails unless exactly one test ran and passed.
#
# Why this exists. The publication properties are read from CI *step names*,
# because the job logs need a token this project does not use and a measurement
# nobody can read is not a measurement. That puts the whole weight of the
# evidence on "the step named for this property went green", so the step has to
# fail when the property did not actually run. Two ways it silently did not,
# both measured rather than assumed:
#
#   * `cargo test -- --exact <name>` exits 0 when the name matches nothing. So
#     dropping one character from a step's filter turns it into a green no-op.
#     Substring filters degraded the other way -- they matched a superset, which
#     is the bug that moving to `--exact` fixed -- so this hole arrived with the
#     fix for the other one.
#   * `cargo test -- --exact <name>` exits 0 when the test it names is
#     `#[ignore]`d, reporting "0 passed; 0 failed; 1 ignored".
#
# An engineering review found both. The `--list` coverage step in the workflow
# catches neither: a `#[ignore]`d test still prints in `--list`, and the step's
# expected-name list is a separate hand-kept copy of the same names.
set -uo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <package> <exact test name>" >&2
  exit 2
fi
package="$1"
name="$2"

output=$(cargo +1.98.1 test -p "$package" --locked -- --exact "$name" 2>&1)
status=$?
printf '%s\n' "$output"
if [ "$status" -ne 0 ]; then
  exit "$status"
fi

# One line per test binary in the package; exactly one of them must report the
# single test as run and passed.
ran=$(printf '%s\n' "$output" | grep -c '^test result: ok\. 1 passed; 0 failed; 0 ignored')
if [ "$ran" -ne 1 ]; then
  echo ""
  echo "FAIL: expected exactly one test named '$name' in $package to run and pass."
  echo "      cargo exited 0, which it also does when the filter matches nothing"
  echo "      and when the named test is #[ignore]d. Neither is a measurement."
  exit 1
fi
