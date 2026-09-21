# pqbit — Post-Quantum Bitcoin

> **Bitcoin as it would be designed in 2026, with fifteen years of hindsight:**
> quantum-resistant from genesis, lightweight by construction, fair-launch by constitution.

Part of [Hartwell Labs](https://bartoszosiej.github.io/) · Founder: Bartosz Osiej

[![Rust](https://img.shields.io/badge/Rust-1.97+-DEA584?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![CI](https://github.com/BartoszOsiej/pqbit/actions/workflows/ci.yml/badge.svg)](https://github.com/BartoszOsiej/pqbit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-9%20passing-brightgreen?style=flat-square)](#verification)

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

**Phase 2 — testnet node (active).** The repository currently provides:

- `pqbit-core` — quantum-resistant transaction model: TxIn/TxOut/Transaction, canonical sighash preimage, PQ signature verification via [bitcoinpqc](https://crates.io/crates/bitcoinpqc) (ML-DSA-44, SLH-DSA-SHA2-128s)
- `pqbit-node` — testnet chain engine: blocks, SHA-256d PoW (leading-zero-bits difficulty), coinbase with height commitment, **UTXO set with ML-DSA spend authorization**, CLI miner
- **9/9 tests** (core 4 + node 5): genesis mining, PoW rejection, valid PQ spend, tampered-signature rejection, double-spend impossibility
- [GENESIS.md](GENESIS.md) — draft v0.1 of genesis parameters, open for public review

Live demo (release build, difficulty 14):

```text
$ pqbit-node mine --blocks 3 --difficulty 14 --reward 50
  block   1  hash=4b2305d2585ecffe…  nonce=     11322  supply=50
  block   2  hash=8450c5d8b73829e4…  nonce=       162  supply=100
  block   3  hash=42b53c7129ad39c7…  nonce=     10575  supply=150
  chain tip  : 42b53c7129ad39c7958819a9a50e82db
  utxos      : 3
  status     : OK — PoW + PQ coinbase committed
```

**Phase 3 (started): peer-to-peer scaffold — length-prefixed framing with a 4 MiB cap, magic/version handshake, Ping/Pong liveness, and full-block **pull sync**: `pqbit-node serve` mines a local chain and serves it; a peer connects, handshakes, `GetBlocks` → applies blocks and lands on our tip (PQ-validated end-to-end; std-only, no new dependencies). Wire spec is the code: explicit field-order codecs in `node/src/net.rs`.

**Next:** addr manager + block push relay (gossip), reorg handling, explorator, whitepaper. Found a real bug with us: the first coinbase design collided txids across blocks (height lived in the uncommitted signature field) — caught by the double-spend test, fixed by committing height in the prevout.

## Quick start

```bash
git clone https://github.com/BartoszOsiej/pqbit
cd pqbit
cargo test
```

## Verification

```text
$ cargo test
running 9 tests (4 core + 5 node)
test tests::sighash_is_deterministic ... ok
test tests::public_key_size_matches_crate_spec ... ok
test tests::tampered_message_is_rejected ... ok
test tests::ml_dsa_keygen_sign_verify_roundtrip ... ok
test chain::tests::genesis_mines_and_applies ... ok
test chain::tests::pow_rejects_low_work_block ... ok
test chain::tests::spend_requires_valid_pq_signature ... ok
test chain::tests::tampered_signature_is_rejected ... ok
test chain::tests::double_spend_is_impossible ... ok
```

## FAQ

**Is this a token sale?** No. Never presale. The only monetary event is mining from genesis.

**Why not just wait for BIP-360 activation on Bitcoin?** If it activates, this project served as a working reference implementation and a research contribution. If the market wants a quantum-resistant chain *now*, pqbit exists. Both outcomes are wins.

**What about quantum-safe but slower signatures?** That's the honest trade-off: PQ signatures are larger (ML-DSA-44 ≈ 2.4 KB vs. Schnorr's 64 B). We budget for it: compact blocks, efficient UTXO commitments, and a light client are core features, not afterthoughts.

**Is the founder stash going to be dumped?** The 100-coin founder address will be published at genesis and watched publicly. It is a reputational bond, not an allocation.

## Acknowledgments

Standing on the shoulders of: [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin), [bitcoinpqc](https://github.com/bitcoinpqc/bitcoinpqc) (the FIPS-certified PQ signature bridge), the BIP-360 authors, and fifteen years of Bitcoin Core engineering discipline.

## Hartwell Labs ecosystem

pqbit is the flagship research project of **Hartwell Labs**:

| Project | What | Landing |
|---|---|---|
| pqbit | Post-quantum Bitcoin | https://bartoszosiej.github.io/pqbit/ |
| quantum-shield | ML-KEM-768 file encryption (pqguard) | https://bartoszosiej.github.io/quantum-shield/ |
| fortis | Post-quantum measured boot | https://bartoszosiej.github.io/fortis/ |
| talus-process-monitor | eBPF ransomware detect & respond | https://bartoszosiej.github.io/talus-process-monitor/ |
| externum | Language compiling to Python/Bash/bytecode | https://bartoszosiej.github.io/externum/ |
| NV2_ENGINE | Voxel engine, neural terrain | https://bartoszosiej.github.io/NV2_ENGINE/ |
| Docs | Full documentation hub (Fumadocs) | https://bartoszosiej.github.io/Docs/ |

## License

MIT — like Bitcoin Core. Built in the open by [Hartwell Labs](https://bartoszosiej.github.io/).
