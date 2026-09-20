# pqbit — Post-Quantum Bitcoin

> **Bitcoin as it would be designed in 2026, with fifteen years of hindsight:**
> quantum-resistant from genesis, lightweight by construction, fair-launch by constitution.

Part of [Hartwell Labs](https://bartoszosiej.github.io/) · Founder: Bartosz Osiej

[![Rust](https://img.shields.io/badge/Rust-1.97+-DEA584?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![CI](https://github.com/BartoszOsiej/pqbit/actions/workflows/ci.yml/badge.svg)](https://github.com/BartoszOsiej/pqbit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-4%20passing-brightgreen?style=flat-square)](#verification)

## Why

~7 million BTC sit in quantum-exposed addresses (ECDSA public keys revealed on-chain). BIP-360 (P2MR) was merged into the Bitcoin BIPs repository in February 2026 — the migration conversation is live, but Bitcoin moves slowly by design.

**pqbit is the chain that doesn't need to migrate — because it was born post-quantum.**

Not "a faster Bitcoin". Not "a better store of value". One thesis, executed cleanly: *take everything Bitcoin got right (UTXO, Proof-of-Work, fixed supply, conservative engineering) and build it on NIST-standardized post-quantum signatures from block one.*

## Constitution (non-negotiable)

| Principle | Commitment |
|---|---|
| **Fair launch** | No premine. No presale. No VC allocation. Founders mine like everyone else. |
| **Founder stash** | Maximum **100 coins**, single public address, publicly declared — and *never moved*. Moving one coin ends the project's narrative. |
| **PQC from genesis** | ML-DSA-44 (FIPS 204) + SLH-DSA-SHA2-128s (FIPS 205). No ECDSA fallback at consensus layer. |
| **Fixed supply** | Capped, predictable emission schedule (final parameters published before genesis). |
| **Lightweight** | Compact blocks + SPV light client. A laptop participates fully — node *and* miner. |
| **Kill criteria** | If 6 months after mainnet genesis fewer than 50 nodes exist outside the founding team, the coin experiment is frozen and the project returns to pure research. No sunk-cost. |

## Status

**Phase 1 — core primitives (active).** This repository currently provides:

- `pqbit-core` — quantum-resistant transaction model: TxIn/TxOut/Transaction, canonical sighash preimage, PQ signature verification via [bitcoinpqc](https://crates.io/crates/bitcoinpqc) (ML-DSA-44, SLH-DSA-SHA2-128s)
- Deterministic sighash scheme over the PQ preimage (double-SHA-256)
- Keypair generation, signing, verification round-trips — **4/4 tests passing**

**Next:** testnet node (Rust, lightweight), genesis parameters draft, explorator, whitepaper.

## Quick start

```bash
git clone https://github.com/BartoszOsiej/pqbit
cd pqbit
cargo test
```

## Verification

```text
$ cargo test
running 4 tests
test tests::sighash_is_deterministic ... ok
test tests::public_key_size_matches_crate_spec ... ok
test tests::tampered_message_is_rejected ... ok
test tests::ml_dsa_keygen_sign_verify_roundtrip ... ok
```

## FAQ

**Is this a token sale?** No. Never presale. The only monetary event is mining from genesis.

**Why not just wait for BIP-360 activation on Bitcoin?** If it activates, this project served as a working reference implementation and a research contribution. If the market wants a quantum-resistant chain *now*, pqbit exists. Both outcomes are wins.

**What about quantum-safe but slower signatures?** That's the honest trade-off: PQ signatures are larger (ML-DSA-44 ≈ 2.4 KB vs. Schnorr's 64 B). We budget for it: compact blocks, efficient UTXO commitments, and a light client are core features, not afterthoughts.

**Is the founder stash going to be dumped?** The 100-coin founder address will be published at genesis and watched publicly. It is a reputational bond, not an allocation.

## License

MIT — like Bitcoin Core. Built in the open by [Hartwell Labs](https://bartoszosiej.github.io/).
