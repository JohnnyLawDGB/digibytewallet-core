#!/usr/bin/env python3
"""Split the Android repo's host KATs into shards for the core CI.

    plan.py <host dir> <timings file> <shard count> <out dir>

Writes <out dir>/all.txt (every *_kat directory, sorted: what run-host-kats.sh would run) and
<out dir>/shard-<i>.txt for i in 0..count-1, one suite name per line.

Deterministic: the same suite list, timings and count always give the same plan. Suites are taken
longest first (name breaking ties) and each goes to the shard with the least planned time so far
(lowest index breaking ties). A suite with no timing is planned at DEFAULT_SECONDS, so a new KAT
is never dropped, only possibly badly placed until the timings are refreshed.

Fails if the shards' union is not exactly all.txt, or a suite lands in two shards.
"""
import os
import sys

DEFAULT_SECONDS = 60


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    host_dir, timings_path, count, out_dir = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    if count < 1:
        sys.exit("shard count must be at least 1")

    # The same selection as run-host-kats.sh: every directory (or link to one) under the host dir
    # whose name ends in _kat. One without a run.sh is still planned: the shard reports it as
    # NO RUNNER and fails, as the full sweep does.
    kats = sorted(
        name for name in os.listdir(host_dir)
        if name.endswith("_kat") and not name.startswith(".")
        and os.path.isdir(os.path.join(host_dir, name))
    )
    if not kats:
        sys.exit(f"no *_kat directories under {host_dir}")

    timings = {}
    with open(timings_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            secs, name = line.split()
            timings[name] = max(1, int(secs))

    def weight(name):
        return timings.get(name, DEFAULT_SECONDS)

    shards = [[] for _ in range(count)]
    load = [0] * count
    for name in sorted(kats, key=lambda k: (-weight(k), k)):
        i = min(range(count), key=lambda j: (load[j], j))
        shards[i].append(name)
        load[i] += weight(name)

    flat = [k for s in shards for k in s]
    if sorted(flat) != kats or len(set(flat)) != len(flat):
        sys.exit("internal error: the shards do not partition the suite list")

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "all.txt"), "w") as f:
        f.writelines(k + "\n" for k in kats)
    for i, s in enumerate(shards):
        with open(os.path.join(out_dir, f"shard-{i}.txt"), "w") as f:
            f.writelines(k + "\n" for k in sorted(s))

    untimed = [k for k in kats if k not in timings]
    print(f"{len(kats)} suites in {count} shards ({sum(load)}s planned in all)")
    for i, s in enumerate(shards):
        print(f"  shard {i}: {len(s):3d} suites, ~{load[i]}s planned")
    if untimed:
        print(f"no timing, planned at {DEFAULT_SECONDS}s: {' '.join(untimed)}")


if __name__ == "__main__":
    main()
