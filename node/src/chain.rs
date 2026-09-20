//! pqbit-node chain: blocks, PoW, UTXO set with post-quantum validation.
//!
//! Testnet-grade primitives (wagons, no networking yet): SHA-256d PoW with
//! difficulty expressed as leading zero bits, UTXO accounting with ML-DSA-44
//! spend authorization via pqbit-core. Phase-2 skeleton a real p2p node grows from.

use pqbit_core::{verify_pq, SigAlgo, Transaction, TxIn, TxOut};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A block in the pqbit testnet chain.
#[derive(Debug, Clone)]
pub struct Block {
    /// Height (genesis = 0).
    pub height: u64,
    /// Hash of the previous block (hex-encoded, "" for genesis).
    pub prev_hash: String,
    /// UNIX timestamp of block creation.
    pub timestamp: u64,
    /// Transactions included in this block (coinbase first).
    pub transactions: Vec<Transaction>,
    /// PoW nonce.
    pub nonce: u64,
}

impl Block {
    /// Canonical block header serialization for hashing/mining.
    pub fn header_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        for tx in &self.transactions {
            buf.extend_from_slice(&tx.sighash());
        }
        buf
    }

    /// Block hash: SHA-256d of the header (hex).
    pub fn hash(&self) -> String {
        let h1 = Sha256::digest(self.header_preimage());
        let h2 = Sha256::digest(h1);
        hex::encode(h2)
    }

    /// Does this block satisfy `difficulty` leading zero bits?
    pub fn meets_target(&self, difficulty: u32) -> bool {
        leading_zero_bits(&Sha256::digest(self.header_preimage())) >= difficulty as usize
    }
}

/// Count leading zero bits of a digest (PoW measure).
pub fn leading_zero_bits(d: &[u8]) -> usize {
    let mut z = 0usize;
    for &b in d {
        if b == 0 {
            z += 8;
        } else {
            z += b.leading_zeros() as usize;
            break;
        }
    }
    z
}

/// Coinbase transaction: mints `reward` sats to `pubkey` (PQ verifying key).
///
/// The block height is committed inside `prev_txid[0..8]` (LE) — the sighash
/// preimage commits prevouts but not signatures, so the height MUST live in a
/// committed field or every coinbase would collide on the same txid.
pub fn coinbase(pubkey: Vec<u8>, reward: u64, height: u64) -> Transaction {
    let mut prev = [0u8; 32];
    prev[0..8].copy_from_slice(&height.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_txid: prev,
            vout: u32::MAX,
            signature: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: reward,
            pubkey,
        }],
        locktime: 0,
    }
}

/// Errors the node can surface.
#[derive(Debug, PartialEq)]
pub enum NodeError {
    BadPrevHash,
    BadPoW,
    Overspend,
    BadSignature,
    DoubleSpend,
    UnknownUtxo,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NodeError::BadPrevHash => "prev_hash does not chain",
            NodeError::BadPoW => "block does not meet PoW target",
            NodeError::Overspend => "outputs exceed inputs",
            NodeError::BadSignature => "PQ signature invalid",
            NodeError::DoubleSpend => "UTXO spent twice",
            NodeError::UnknownUtxo => "input references unknown UTXO",
        };
        f.write_str(s)
    }
}
impl std::error::Error for NodeError {}

/// The UTXO set + chain tip state.
#[derive(Default)]
pub struct ChainState {
    /// key: (txid_hex, vout) -> value + pubkey
    pub utxos: HashMap<(String, u32), (u64, Vec<u8>)>,
    pub tip_height: u64,
    pub tip_hash: String,
    pub total_supply: u64,
    pub difficulty: u32,
}

impl ChainState {
    pub fn new(difficulty: u32) -> Self {
        Self {
            difficulty,
            ..Default::default()
        }
    }

    /// Append a validated block: PoW, chaining, coinbase, every spend PQ-verified.
    pub fn apply_block(&mut self, block: &Block, reward: u64) -> Result<(), NodeError> {
        // 1. chaining
        if block.height != self.tip_height + 1 || block.prev_hash != self.tip_hash {
            return Err(NodeError::BadPrevHash);
        }
        // 2. PoW
        if !block.meets_target(self.difficulty) {
            return Err(NodeError::BadPoW);
        }
        // 3. transactions
        let mut minted = 0u64;
        for (idx, tx) in block.transactions.iter().enumerate() {
            if idx == 0 {
                // coinbase: no inputs to verify, mints reward
                let out = tx
                    .outputs
                    .first()
                    .ok_or(NodeError::Overspend)?;
                minted = out.value;
                if minted > reward {
                    return Err(NodeError::Overspend);
                }
            } else {
                self.apply_spend(tx)?;
            }
        }
        // 4. commit coinbase output
        if let Some(cb) = block.transactions.first() {
            if let Some(out) = cb.outputs.first() {
                let txid = hex::encode(cb.sighash());
                self.utxos
                    .insert((txid, 0u32), (out.value, out.pubkey.clone()));
            }
        }
        self.total_supply += minted;
        self.tip_height = block.height;
        self.tip_hash = block.hash();
        Ok(())
    }

    /// Verify and apply one spend transaction against the UTXO set.
    fn apply_spend(&mut self, tx: &Transaction) -> Result<(), NodeError> {
        let sighash = tx.sighash();
        let mut spent_keys = Vec::new();
        let mut input_sum = 0u64;

        for txin in &tx.inputs {
            let key = (hex::encode(txin.prev_txid), txin.vout);
            let (value, pubkey) = self
                .utxos
                .get(&key)
                .cloned()
                .ok_or(NodeError::UnknownUtxo)?;
            // post-quantum authorization: ML-DSA-44 over the sighash
            let ok = verify_pq(SigAlgo::MlDsa44, &pubkey, &sighash, &txin.signature)
                .map_err(|_| NodeError::BadSignature)?;
            if !ok {
                return Err(NodeError::BadSignature);
            }
            spent_keys.push(key);
            input_sum += value;
        }

        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if output_sum > input_sum {
            return Err(NodeError::Overspend);
        }

        // remove spent, add change outputs
        for k in spent_keys {
            if self.utxos.remove(&k).is_none() {
                return Err(NodeError::DoubleSpend);
            }
        }
        let txid = hex::encode(sighash);
        for (i, out) in tx.outputs.iter().enumerate() {
            self.utxos.insert((txid.clone(), i as u32), (out.value, out.pubkey.clone()));
        }
        Ok(())
    }
}

/// Simple miner: increment nonce until target met.
pub fn mine_block(mut block: Block, difficulty: u32, max_nonce: u64) -> Option<Block> {
    for nonce in 0..max_nonce {
        block.nonce = nonce;
        if block.meets_target(difficulty) {
            return Some(block);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqbit_core::generate_pq_keypair;

    const D: u32 = 8; // testnet-toy difficulty: 8 leading zero bits

    fn mine_next(state: &ChainState, miner_pk: Vec<u8>, reward: u64) -> Block {
        let b = Block {
            height: state.tip_height + 1,
            prev_hash: state.tip_hash.clone(),
            timestamp: 1_700_000_000 + state.tip_height,
            transactions: vec![coinbase(miner_pk, reward, state.tip_height + 1)],
            nonce: 0,
        };
        mine_block(b, state.difficulty, 10_000_000).expect("mine within budget")
    }

    #[test]
    fn genesis_mines_and_applies() {
        let mut st = ChainState::new(D);
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let blk = mine_next(&st, kp.public_key.bytes.clone(), 50);
        st.apply_block(&blk, 50).unwrap();
        assert_eq!(st.tip_height, 1);
        assert_eq!(st.total_supply, 50);
        assert_eq!(st.utxos.len(), 1);
    }

    #[test]
    fn pow_rejects_low_work_block() {
        let mut st = ChainState::new(D);
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let mut blk = Block {
            height: 1,
            prev_hash: String::new(),
            timestamp: 0,
            transactions: vec![coinbase(kp.public_key.bytes.clone(), 50, 1)],
            nonce: 0,
        };
        // find a nonce that does NOT meet target (easy at D=8: most don't)
        let mut found_low = false;
        for nonce in 0..10_000u64 {
            blk.nonce = nonce;
            if !blk.meets_target(D) {
                found_low = true;
                break;
            }
        }
        assert!(found_low, "expected a low-work nonce to exist");
        assert_eq!(st.apply_block(&blk, 50), Err(NodeError::BadPoW));
    }

    #[test]
    fn spend_requires_valid_pq_signature() {
        // build chain of 2 blocks: miner A mines twice
        let mut st = ChainState::new(D);
        let a = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        for _ in 0..2 {
            let blk = mine_next(&st, a.public_key.bytes.clone(), 50);
            st.apply_block(&blk, 50).unwrap();
        }

        // A spends one UTXO to B with a REAL ML-DSA signature
        let b = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let ((txid, vout), (value, _)) = st.utxos.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                vout,
                signature: vec![],
            }],
            outputs: vec![TxOut {
                value,
                pubkey: b.public_key.bytes.clone(),
            }],
            locktime: 0,
        };
        let sig = pqbit_core::sign_pq(SigAlgo::MlDsa44, &a.secret_key.bytes, &spend.sighash())
            .unwrap();
        spend.inputs[0].signature = sig;

        let blk = Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_100,
            transactions: vec![coinbase(a.public_key.bytes.clone(), 50, st.tip_height + 1), spend],
            nonce: 0,
        };
        let blk = mine_block(blk, D, 10_000_000).unwrap();
        st.apply_block(&blk, 50).unwrap();
        assert_eq!(st.tip_height, 3);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut st = ChainState::new(D);
        let a = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let blk = mine_next(&st, a.public_key.bytes.clone(), 50);
        st.apply_block(&blk, 50).unwrap();

        let b = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let ((txid, vout), (value, _)) = st.utxos.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                vout,
                signature: vec![0xAA; 100], // garbage
            }],
            outputs: vec![TxOut {
                value,
                pubkey: b.public_key.bytes.clone(),
            }],
            locktime: 0,
        };
        let _ = &mut spend;
        let blk = Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_200,
            transactions: vec![coinbase(a.public_key.bytes.clone(), 50, st.tip_height + 1), spend],
            nonce: 0,
        };
        let blk = mine_block(blk, D, 10_000_000).unwrap();
        assert_eq!(st.apply_block(&blk, 50), Err(NodeError::BadSignature));
    }

    #[test]
    fn double_spend_is_impossible() {
        let mut st = ChainState::new(D);
        let a = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let blk = mine_next(&st, a.public_key.bytes.clone(), 50);
        st.apply_block(&blk, 50).unwrap();

        let ((txid, vout), (value, _)) = st.utxos.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let make_spend = |to: &Vec<u8>| {
            let mut tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                    vout,
                    signature: vec![],
                }],
                outputs: vec![TxOut {
                    value,
                    pubkey: to.clone(),
                }],
                locktime: 0,
            };
            tx.inputs[0].signature =
                pqbit_core::sign_pq(SigAlgo::MlDsa44, &a.secret_key.bytes, &tx.sighash()).unwrap();
            tx
        };
        let b = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let c = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();

        // spend 1: B gets coins (block 2)
        let s1 = make_spend(&b.public_key.bytes);
        let blk1 = Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_300,
            transactions: vec![coinbase(a.public_key.bytes.clone(), 50, st.tip_height + 1), s1],
            nonce: 0,
        };
        let blk1 = mine_block(blk1, D, 10_000_000).unwrap();
        st.apply_block(&blk1, 50).unwrap();

        // spend 2: same UTXO to C (block 3) — must fail: UTXO already consumed
        let s2 = make_spend(&c.public_key.bytes);
        let blk2 = Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_400,
            transactions: vec![coinbase(a.public_key.bytes.clone(), 50, st.tip_height + 1), s2],
            nonce: 0,
        };
        let blk2 = mine_block(blk2, D, 10_000_000).unwrap();
        let res = st.apply_block(&blk2, 50);
        assert_eq!(res, Err(NodeError::UnknownUtxo));
    }
}
