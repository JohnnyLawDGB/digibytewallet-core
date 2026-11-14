#!/usr/bin/env python3
# Vectors for BRDandelionEmbargo.h's delay: Android's arithmetic, computed here and NOT by the
# header, so the host KAT dandelion_embargo_kat holds the header to Android rather than to itself.
#
# The model is DandelionBroadcastPolicy.kt:32-35 (digibytewallet-android v4.1.3) as the JVM runs it:
#     EMBARGO_MIN_MS + (rng01.coerceIn(0.0, 1.0) * (EMBARGO_MAX_MS - EMBARGO_MIN_MS)).toLong()
# with rng01 = draw * 2^-53, which is what Random.nextDouble returns (Broadcaster.kt:65,
# SecureRandom). Python floats are IEEE 754 binary64 with round-to-nearest-even, as Java's
# doubles are; int() truncates toward zero, as Kotlin's Double.toLong() does for these values.
# For a draw below 2^53, float(draw) and the scaling by 2^-53 are exact and the multiply by
# 20000.0 is the only rounding, exactly as on the JVM. A draw at or above 2^53 (never drawn; the
# header's input type allows it) scales to at least 1.0 and coerceIn clamps it to 1.0.
#
# The corpus: the edges, Android's own test inputs (DandelionBroadcastPolicyTest.kt: 0.0, 0.5,
# 0.999, 1.0, as draws), 200 of the draws within 3 of a millisecond boundary where the double's
# rounding carries the product up to the next millisecond (the draws an exact integer quotient
# gets 1 ms short; 7434 of them in all), 200 boundary draws where it does not, both taken at an
# even stride through the sorted lists, and 500 pseudo-random draws from SplitMix64 written out
# here, so the file depends on no library's random module and is the same on every Python 3.
#
# Regenerate, from this directory:
#   python3 -I generate.py > vectors.txt

LIMIT = 1 << 53


def android_delay(draw):
    rng01 = float(draw) * 2.0 ** -53
    rng01 = min(max(rng01, 0.0), 1.0)          # coerceIn(0.0, 1.0)
    return 10000 + int(rng01 * float(30000 - 10000))


def quotient(draw):                            # the exact quotient, for classifying draws only
    return 10000 + (draw * 20000 >> 53) if draw < LIMIT else 30000


rows = []                                      # (draw, why)
for d, why in [(0, "zero"), (1, "one"), (2, "two"), (LIMIT >> 1, "half"),
               (LIMIT - 1, "max_draw"), (LIMIT - 2, "max_draw_minus_1"),
               (LIMIT, "limit_clamps"), (LIMIT + 1, "above_limit_clamps"),
               ((1 << 64) - 1, "u64_max_clamps"),
               (int(0.999 * LIMIT), "kotlin_test_0_999"), (LIMIT >> 1, "kotlin_test_0_5"),
               (0, "kotlin_test_0_0"), (LIMIT, "kotlin_test_1_0")]:
    rows.append((d, why))

carry, plain = [], []
for m in range(1, 20000):
    base = (m << 48) // 625
    for d in range(base - 3, base + 4):
        if not 0 <= d < LIMIT:
            continue
        (carry if android_delay(d) != quotient(d) else plain).append(d)


def every(xs, n):                             # n entries at an even stride through sorted xs
    xs = sorted(xs)
    return [xs[i * len(xs) // n] for i in range(n)]


for d in every(carry, 200):
    rows.append((d, "rounds_up"))
for d in every(plain, 200):
    rows.append((d, "boundary"))

M64 = (1 << 64) - 1
state = 20261113
for _ in range(500):                           # SplitMix64; the top 53 bits of each output
    state = (state + 0x9E3779B97F4A7C15) & M64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    z ^= z >> 31
    rows.append((z >> 11, "random"))

print("# BRDandelionEmbargo.h delay vectors: Android's DandelionBroadcastPolicy.kt arithmetic, computed by")
print("# vectors/dandelion-embargo/generate.py (not by the header); do not edit. dandelion_embargo_kat checks")
print("# the header against every line.")
print("# delay <draw, decimal uint64> <ms> <why>")
for d, why in rows:
    print("delay %d %d %s" % (d, android_delay(d), why))
print("# %d lines; %d of %d rounds_up draws" % (len(rows), 200, len(carry)))
