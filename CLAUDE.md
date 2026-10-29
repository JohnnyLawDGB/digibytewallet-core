# CLAUDE.md — digibytewallet-core

The C core both wallets ship: Android through JNI (`digibytewallet-android`, submodule at
`native/src/main/jni/digibytewallet-core`) and iOS as an XCFramework (`digibytewallet-ios`,
private). Same seed, two platforms, one wallet state: any rule that can change wallet state or
wire behaviour lives here, not in Kotlin or Swift.

**Read:** the Android repo's `CLAUDE.md` (authoritative for every decision the core encodes),
its `docs/development-process.md` (how PRs here are reviewed and merged, and how agents split
the work), and its `docs/ios-port/push-down-recipe.md` (how a rule moves into the core).

- **Tests live in the Android repo** as host KATs (`native/src/test/host/`,
  `scripts/run-host-kats.sh`). A core change ships with its KAT there: green on the fix, and
  each red arm (a `*_UNFIXED` or `*_RED_*` macro here) fails exactly its cases.
- **Merge commits or fast-forwards into `develop`, never a squash.** Both apps pin core commits,
  and a pin must stay reachable from `develop`.
- **This repo is public.** No private-advisory or bounty details; name a finding by ID and
  state the invariant.
