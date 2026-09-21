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

**Phase 3 (in progress): peer-to-peer — length-prefixed framing with a 4 MiB cap, magic/version handshake, Ping/Pong liveness, full-block pull sync, and now **gossip**: an addr manager (`GETADDR`/`ADDR` + self-announcement, so one seed reveals the mesh) and push/pull relay — `pqbit-node serve --seed host:port` mines a local chain, then exchanges addr books and blocks with peers on a timer: pull when they are taller, push when we are. Every arriving block goes through the full PQ chain validation before it touches our tip. A bounded mempool (4096 txs, FIFO eviction, duplicate/conflict protection, read-only ML-DSA validation before admission) now feeds the miner: `serve` packs pooled spends into new blocks on top of the coinbase, `--keep-mining` mints continuously, and gossip rounds now relay mempool transactions too (TX/GETMEMPOOL/MEMPOOL) — chain sync always precedes mempool sync, because a spend can only validate once its prevout exists. 21 tests incl. an end-to-end two-node convergence test; std-only, no new dependencies). Wire spec is the code: explicit field-order codecs in `node/src/net.rs`.

**Fork choice is in: longest-chain reorg (v1).** A same-height sibling is stashed; when a taller branch is fully known it wins by replay from genesis, orphaned blocks' txs return to the mempool (24 tests incl. a fork/reorg scenario). **Next:** persistent peers, rate limiting, explorer, whitepaper. Found a real bug with us: the first coinbase design collided txids across blocks (height lived in the uncommitted signature field) — caught by the double-spend test, fixed by committing height in the prevout.

## Quick start

```bash
git clone https://github.com/BartoszOsiej/pqbit
cd pqbit
cargo test --release          # 24 tests: core, chain, p2p, mempool, wallet cycle

# generate a wallet (payout address + signing key):
cargo run -p pqbit --bin pqbit-node -- wallet --write

# mine to YOUR address, export the UTXO set, check the balance:
cargo run -p pqbit --bin pqbit-node -- mine --blocks 3 --difficulty 12 \
  --payout <public-key-hex> --dump-utxos utxos.txt --extended
cargo run -p pqbit --bin pqbit-node -- balance \
  --address <public-key-hex> --utxos utxos.txt

# sign a spend of an owned UTXO (self-verifies the signature before writing):
cargo run -p pqbit --bin pqbit-node -- send \
  --pk pqbit.pk --sk pqbit.sk --owned utxos.txt \
  --to <recipient-pubkey-hex> --out tx.hex

# validate a signed tx against the UTXO set (offline check):
cargo run -p pqbit --bin pqbit-node -- submit --tx tx.hex --utxos utxos.txt

# push a signed tx to a LIVE node: it validates into its mempool and the
# next mined block packs it (end-to-end transfer):
cargo run -p pqbit --bin pqbit-node -- broadcast --addr 127.0.0.1:18444 --tx tx.hex

# run a node that mines and gossips:
cargo run -p pqbit --bin pqbit-node -- serve \
  --blocks 5 --difficulty 12 --listen 127.0.0.1:18444 --keep-mining

# a second node joins by seed and syncs (blocks + mempool):
cargo run -p pqbit --bin pqbit-node -- serve \
  --blocks 0 --difficulty 12 --listen 127.0.0.1:18445 \
  --seed 127.0.0.1:18444 --interval 5 --keep-mining
```

Anyone can run a node and mine by the same rules — the founder has no
privilege beyond a ≤100-coin stash that can never be spent (see
[GENESIS.md](GENESIS.md)).

## Verification

All 24 tests pass in CI on every push (unit, chain, wire-codec, gossip
convergence, mempool relay, fork-choice reorg). Run locally:

```bash
cargo test --release
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
