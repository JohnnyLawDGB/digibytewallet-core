#!/usr/bin/env bash
# Run one shard of the host KATs, one suite at a time, through the Android repo's own runner.
#
#   run-shard.sh <android checkout> <shard list> <results file>
#
# Each suite goes through `scripts/run-host-kats.sh <name>` unchanged, so it gets the same
# compiler choice and shipped header check levels as the full sweep. One suite at a time: a
# runner shared by several ASan builds is where the rc=137 (out of memory) kills came from, and a
# retry would hide a real failure, so there is none.
#
# The runner's filter is a substring match, so a name contained in another suite's name runs both;
# every suite line the runner prints is recorded, not only the one asked for. The results file
# gets one line per suite run: "<name> <PASS|FAIL|NO_RUNNER|MISSING> <seconds>". MISSING means the
# runner never printed a line for the suite it was asked to run.
#
# Exit 0 only if every suite in the list passed.
set -uo pipefail

android="$1"; list="$2"; results="$3"
logdir="$(mktemp -d)"
: > "$results"
fail=0; ran=0

while IFS= read -r name; do
    [ -n "$name" ] || continue
    ran=$((ran + 1))
    log="$logdir/$name.log"
    start=$SECONDS
    rc=0
    (cd "$android" && ./scripts/run-host-kats.sh "$name") > "$log" 2>&1 || rc=$?
    secs=$((SECONDS - start))

    # Suite lines are printf '%-32s %s': name, spaces, status. Status words: PASS, FAIL, NO RUNNER.
    status=MISSING
    while read -r suite word rest; do
        [ "$word" = NO ] && word=NO_RUNNER
        if [ "$suite" = "$name" ]; then
            status="$word"
        else
            echo "$suite $word $secs" >> "$results"   # ran too: the filter matched it as well
        fi
    done < <(grep -E '^[A-Za-z0-9._-]+_kat +(PASS|FAIL|NO RUNNER)$' "$log")
    # A suite that printed PASS but whose runner still exited non-zero is not a pass.
    [ "$status" = PASS ] && [ "$rc" -ne 0 ] && status=FAIL
    echo "$name $status $secs" >> "$results"

    printf '%-40s %-9s %5ss\n' "$name" "$status" "$secs"
    if [ "$status" != PASS ]; then
        fail=$((fail + 1))
        echo "::error::$name: $status (runner exit $rc)"
        sed 's/^/    | /' "$log"
    fi
done < "$list"

rm -rf "$logdir"
echo
echo "shard: $ran suites, $fail not passed (${SECONDS}s)"
[ "$ran" -gt 0 ] && [ "$fail" -eq 0 ]
