# `random-beacon-export`

Vendored copies of `@keep-network/random-beacon`'s `export/deploy` scripts,
under `./deploy/`. Resolved by `hardhat.config.ts:resolveRandomBeaconExport()`
as the second preference after `../random-beacon/export/` (gitignored
upstream) and before the published
`node_modules/@keep-network/random-beacon/export`.

This README lives one level above `deploy/` because hardhat-deploy walks
that directory and tries to `require()` every file; a Markdown sibling
there would crash deployment.

## Format

These files intentionally mix two formats:

- **`01..04, 06..09_*.js`**: `tsc`-compiled ES5 output from the upstream
  package's TypeScript sources (`__awaiter` / `__generator` runtime helpers,
  `var` declarations). Treat as build artifacts; do not hand-edit.
- **`05_approve_random_beacon_in_token_staking.js`**: hand-written modern
  async/await. Adds an `ifaceHasFunction("approveApplication")` precheck plus
  an exception backstop so the script is idempotent against the Threshold
  `TokenStaking` ABI (which does not expose `approveApplication`).
  **Do not regenerate from upstream without preserving this precheck** —
  blind regeneration will reintroduce a hard failure on networks running the
  Threshold staking contract.

## Known limitation: verification is not wrapped

Unlike the hand-maintained ECDSA deploy scripts (which route Etherscan/Tenderly
verification through `verifyOnEtherscanOrContinue` / `verifyOnTenderlyOrContinue`
so explorer outages never abort a deploy), the `tsc`-compiled vendored scripts
call `helpers.etherscan.verify(...)` / `hre.tenderly.verify(...)` directly. A
verification failure (rate limit, bytecode mismatch, missing key) in one of
these scripts can therefore halt the deploy.

This is accepted rather than patched: these are build artifacts and must not be
hand-edited (see Format above). If it becomes a recurring operational problem,
fix it upstream in `@keep-network/random-beacon`'s `export/deploy` sources and
re-vendor, or set `DISABLE_HARDHAT_VERIFY` / the network's verify tags off for
the run.

## Regeneration policy

When syncing from upstream:

1. Regenerate `01..04, 06..09_*.js` from `@keep-network/random-beacon`'s
   `export/deploy` source via its `tsc` build.
2. **Skip `05_*.js`** during regeneration, or re-apply the
   `ifaceHasFunction` precheck and the try/catch around `execute(...)` after
   regenerating.
3. Verify by running deploys against both a network that exposes
   `approveApplication` (legacy Keep TokenStaking) and one that does not
   (Threshold TokenStaking).
