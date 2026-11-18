# sp1-reputation (prototype, execute mode only)

An [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zkVM program that takes raw
[agentwork](https://github.com/xbtMelchizedek/agentwork) agb1 lines and a scoring time, and
**commits to the reputation result**:

1. verifies every message: canonical re-encoding, `cid = sha256("FLOP::agb::v1|" + canonical)`,
   Ed25519 signature from the `did:key`. Bad lines are dropped and counted.
2. applies the receipt `supersedes` chain rule (agentwork SPEC §3, main @ 307e52a)
3. applies reputation v0 eligibility (settled tip, claim link, third-party attestation majority,
   window)
4. computes **rep-v0-int**, an integer version of reputation v0 (see `lib/src/lib.rs`)
5. commits ABI-encoded `RepCommitment {logRoot, paramsHash, nowMs, subject, subjectScore,
   subjectReceipts, scoresRoot, validMessages, droppedMessages}`

**Status:** execute mode only. No proof has been generated, nothing was sent to the Succinct
Prover Network, and no PROVE was spent.

## Test

```bash
# native: matches agentwork's supersede-v1 vectors (tips + counted)
cd lib && AGB_VECTORS=/path/to/agentwork/vectors/supersede-v1.json cargo test --release
# zkVM executor: public values == native, tips/counted == vectors, tampered sig dropped
cd script && cargo run --release -- --vectors /path/to/agentwork/vectors/supersede-v1.json
```

Result (Nov 17 2026): 7/7 scenarios plus a tamper case pass. The zkVM output equals the native
output byte for byte. The subject score is 100000 micro-units wherever agentwork's Python gives
0.1, and 0 wherever it gives nothing. Each scenario takes about 5.6–8.6M RISC-V cycles (6–9
messages) without SP1's precompile-patched `sha2`/`ed25519` crates.

## Limits

- rep-v0-int is integer and uses step age-decay, so scores match the float v0 only up to
  rounding. Flags and `min_attester_score` aren't implemented.
- The proof covers "this score follows from these signed messages." It doesn't cover "these are
  all the messages." A missing-receipt (censorship) attack needs the log itself to be committed
  somewhere, e.g. agb1 lineage checkpoints or an on-chain root.
- Proving with `--prove` locally needs a lot of RAM/GPU and wasn't attempted. Network proving
  costs PROVE and needs palmer's approval.
- Doesn't mirror agentwork's newer collusion rules yet (attester-conflict and trade-ring discounts,
  agentwork PR #30).
- Also passes natively against the 12-scenario supersede vectors (agentwork PR #26), Nov 18 2026.
- Possible proof target besides EVM gateways: the FLOP devnet runtime includes a
  `SettlementSp1Pallet` (zkVerify-derived). The proof format and SP1 version it accepts are unverified.

## License

MIT, see `LICENSE-MIT`.
