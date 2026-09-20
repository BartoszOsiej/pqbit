# pqbit Genesis Parameters — DRAFT v0.1 (open review)

> **Status: DRAFT.** Nothing here is final. This document exists so the community
> can tear it apart **before** genesis, not after. Comment via GitHub Issues on
> [BartoszOsiej/pqbit](https://github.com/BartoszOsiej/pqbit) or Telegram [@hartwell_info](https://t.me/hartwell_info).

Proposed by: Hartwell Labs (Bartosz Osiej, founder) · 2026-09-20

## 1. Monetary policy

| Parameter | Proposed value | Rationale |
|---|---|---|
| **Supply cap** | **21,000,000** pqc | Same scarcity contract as Bitcoin. Reinventing this number buys nothing and costs trust. |
| **Divisibility** | 8 decimals (`pq-sat`) | Tooling compatibility; wallets/explorers reuse Bitcoin conventions. |
| **Block interval** | **5 minutes** | 10 min was tuned for 2010 hardware. 5 min halves confirmation latency at the same security-per-day; final decision after testnet latency data. |
| **Initial reward** | **50 pqc/block** | Halving every 210,000 blocks (~2 years at 5 min blocks). Supply curve mirrors BTC, shifted for the shorter interval. |
| **Emission end** | ~2140 equivalent | Standard asymptotic halving. |

## 2. Consensus & cryptography

| Parameter | Proposed value | Rationale |
|---|---|---|
| **Signature (primary)** | **ML-DSA-44** (FIPS 204) | Compact (≈2.4 KB sig, 1312 B pk), fast verify, NIST-standardized. |
| **Signature (alt)** | **SLH-DSA-SHA2-128s** (FIPS 205) | Conservative hash-based option; same UTXO model, different output type. |
| **Legacy ECDSA** | **None. No fallback. Ever.** | The entire thesis. No migration path = no migration debate. |
| **Hash** | SHA-256d (PoW), SHA-256 (commitments) | Battle-tested; no exotic primitives. |
| **PoW** | *Undecided — see §4 open questions.* Candidates: RandomX-class (CPU-friendly) vs Equihash-class (memory-hard). Decision lands with testnet data. |

## 3. Founders & allocation

| Item | Commitment |
|---|---|
| **Premine / presale** | **Zero.** There is no allocation to buy, join, or negotiate. |
| **Founder stash** | **≤ 100 pqc**, single public address, published at genesis, **never spent**. Watched publicly; one moved coin voids the project's own narrative. |
| **Lab revenue** | Around the protocol only: grants, enterprise support, documentation. Never token sales. |
| **Kill criteria** | < 50 non-founder nodes 6 months after genesis → coin experiment frozen, project reverts to research. Pre-signed exit, no sunk cost. |

## 4. Open questions (we are wrong about something — help find what)

1. **PoW algorithm.** CPU-friendly maximizes early distribution but botnets exist; ASIC-resistant claims age badly. Leaning memory-hard, not ASIC-*proof* — nothing is.
2. **Block size / PQ weight budget.** ML-DSA sigs are ~37× larger than Schnorr. Compact blocks + UTXO commitments help, but the right block weight unit is an open modeling problem.
3. **5 vs 10 minute blocks.** Shorter = faster confirmations, more orphan risk. Testnet will decide.
4. **SLH-DSA rollout.** Day-one alt output type, or ML-DSA-only at genesis with SLH-DSA added by soft-flag later? (Leaning: day one — "born safe" should not have an asterisk.)

## 5. What is NOT being decided here

Marketing, exchanges, "community funds", airdrops, partnerships. Genesis parameters only. The chain either earns its users or it doesn't.

---

* pqbit repo: https://github.com/BartoszOsiej/pqbit
* Phase 2 node (blocks, PoW, PQ-validated UTXO): `node/src/chain.rs` — 9/9 tests
* Landing: https://bartoszosiej.github.io/pqbit/
