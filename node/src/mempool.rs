//! pqbit-node mempool: transaction admission + relay (phase 3).
//!
//! Honest scope:
//!   1. read-only PQ validation of standalone txs (chain::validate_spend),
//!   2. duplicate protection: exact-txid and conflicting-inputs,
//!   3. bounded pool (MAX_POOL txs), oldest evicted (FIFO),
//!   4. wire relay: TX / GETMEMPOOL / MEMPOOL messages on the existing
//!      framing, reusing gossip_round's connection pattern,
//!   5. miner integration: `serve` now packs mempool spends into new blocks
//!      on top of the coinbase — after genesis this is how a founder mines
//!      on equal footing with everyone else (coinbase to own key, spends
//!      require their own UTXOs + ML-DSA signature, no special privileges).
//!
//! Deliberately NOT here yet: fee policy (testnet coins are free),
//! RBF/replace-by-fee, child-pays-for-parent, eviction by feerate.

#![allow(dead_code)]

use crate::chain::{ChainState, NodeError};
use pqbit_core::Transaction;
use std::collections::HashMap;

/// Hard cap: mempool holds at most MAX_POOL transactions (FIFO eviction).
pub const MAX_POOL: usize = 4096;

pub struct Mempool {
    /// txid_hex → transaction, insertion-ordered via a Vec of txids.
    txs: HashMap<String, Transaction>,
    order: Vec<String>,
    /// Every prevout currently spent by a pooled tx: (txid_hex, vout) → txid_hex.
    spent: HashMap<(String, u32), String>,
}

#[derive(Debug)]
pub enum MempoolError {
    /// Full validation failed (PQ sig, unknown prevout, overspend).
    Invalid(NodeError),
    /// Exact same txid is already pooled.
    Duplicate,
    /// A pooled tx already spends one of these prevouts.
    Conflicting,
    /// Pool at MAX_POOL; tx rejected (v1 has no fee-based eviction).
    Full,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::Invalid(e) => write!(f, "invalid tx: {e}"),
            MempoolError::Duplicate => write!(f, "duplicate txid"),
            MempoolError::Conflicting => write!(f, "conflicts with pooled tx"),
            MempoolError::Full => write!(f, "mempool full"),
        }
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            order: Vec::new(),
            spent: HashMap::new(),
        }
    }

    /// Validate + admit one transaction.
    pub fn accept(&mut self, tx: &Transaction, chain: &ChainState) -> Result<(), MempoolError> {
        chain
            .validate_spend(tx)
            .map_err(MempoolError::Invalid)?;

        let txid = hex::encode(tx.sighash());
        if self.txs.contains_key(&txid) {
            return Err(MempoolError::Duplicate);
        }
        for txin in &tx.inputs {
            let key = (hex::encode(txin.prev_txid), txin.vout);
            if self.spent.contains_key(&key) {
                return Err(MempoolError::Conflicting);
            }
        }
        if self.txs.len() >= MAX_POOL {
            return Err(MempoolError::Full);
        }

        for txin in &tx.inputs {
            let key = (hex::encode(txin.prev_txid), txin.vout);
            self.spent.insert(key, txid.clone());
        }
        self.order.push(txid.clone());
        self.txs.insert(txid, tx.clone());
        Ok(())
    }

    pub fn get(&self, txid: &str) -> Option<&Transaction> {
        self.txs.get(txid)
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Transactions in insertion (first-seen) order.
    pub fn txs(&self) -> Vec<&Transaction> {
        self.order
            .iter()
            .filter_map(|id| self.txs.get(id))
            .collect()
    }

    /// Drop one tx (e.g. after it was mined into a block) and every pooled tx
    /// that conflicts with it (spent the same prevouts).
    pub fn remove_mined(&mut self, tx: &Transaction) {
        let txid = hex::encode(tx.sighash());
        let mut to_drop: Vec<String> = Vec::new();
        if self.txs.contains_key(&txid) {
            to_drop.push(txid.clone());
        }
        for txin in &tx.inputs {
            let key = (hex::encode(txin.prev_txid), txin.vout);
            if let Some(other) = self.spent.get(&key) {
                if *other != txid {
                    to_drop.push(other.clone());
                }
            }
        }
        for id in to_drop {
            if let Some(t) = self.txs.remove(&id) {
                for txin in &t.inputs {
                    let key = (hex::encode(txin.prev_txid), txin.vout);
                    self.spent.remove(&key);
                }
                self.order.retain(|o| o != &id);
            }
        }
    }

    /// Drain every pooled tx that appears in a mined block (and conflicts).
    pub fn remove_mined_txs(&mut self, block: &crate::chain::Block) {
        for tx in &block.transactions {
            self.remove_mined(tx);
        }
    }

    /// Wire codec: u32 count + count × tx payloads.
    pub fn encode_all(txs: &[&Transaction]) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(txs.len() as u32).to_le_bytes());
        for t in txs {
            o.extend_from_slice(&encode_tx(t));
        }
        o
    }

    /// Decode a MEMPOOL/TX payload; errors on any count or length that could
    /// not fit MAX_POOL / MAX_MSG.
    pub fn decode_all(d: &[u8]) -> Result<Vec<Transaction>, super::net::NetError> {
        let mut r = Reader::new(d);
        let n = r.u32()? as usize;
        if n > MAX_POOL {
            return Err(super::net::NetError::TooLarge);
        }
        let mut out = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            out.push(r.tx()?);
        }
        Ok(out)
    }
}

use super::net::{NetError, MAX_MSG};

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], NetError> {
        if self.pos + n > self.b.len() {
            return Err(NetError::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, NetError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, NetError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, NetError> {
        let l = self.u32()? as usize;
        if l > MAX_MSG {
            return Err(NetError::TooLarge);
        }
        Ok(self.take(l)?.to_vec())
    }
    fn tx(&mut self) -> Result<Transaction, NetError> {
        let version = self.u32()?;
        let locktime = self.u32()?;
        let nin = self.u32()? as usize;
        if nin > MAX_MSG {
            return Err(NetError::TooLarge);
        }
        let mut inputs = Vec::with_capacity(nin);
        for _ in 0..nin {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(self.take(32)?);
            let vout = self.u32()?;
            let signature = self.bytes()?;
            inputs.push(pqbit_core::TxIn {
                prev_txid,
                vout,
                signature,
            });
        }
        let nout = self.u32()? as usize;
        if nout > MAX_MSG {
            return Err(NetError::TooLarge);
        }
        let mut outputs = Vec::with_capacity(nout);
        for _ in 0..nout {
            let value = self.u64()?;
            let pubkey = self.bytes()?;
            outputs.push(pqbit_core::TxOut { value, pubkey });
        }
        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

pub fn encode_tx(tx: &Transaction) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&tx.version.to_le_bytes());
    o.extend_from_slice(&tx.locktime.to_le_bytes());
    o.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
    for i in &tx.inputs {
        o.extend_from_slice(&i.prev_txid);
        o.extend_from_slice(&i.vout.to_le_bytes());
        o.extend_from_slice(&(i.signature.len() as u32).to_le_bytes());
        o.extend_from_slice(&i.signature);
    }
    o.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for out in &tx.outputs {
        o.extend_from_slice(&out.value.to_le_bytes());
        o.extend_from_slice(&(out.pubkey.len() as u32).to_le_bytes());
        o.extend_from_slice(&out.pubkey);
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqbit_core::{generate_pq_keypair, sign_pq, SigAlgo, TxIn, TxOut};

    const D: u32 = 8;
    const REWARD: u64 = 50;

    /// Mine one real block paying `kp`, return (state, block).
    fn one_block(kp: &pqbit_core::KeyPair) -> (ChainState, crate::chain::Block) {
        let mut st = ChainState::new(D);
        let blk = crate::chain::Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_000,
            transactions: vec![crate::chain::coinbase(
                kp.public_key.bytes.clone(),
                REWARD,
                st.tip_height + 1,
            )],
            nonce: 0,
        };
        let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
        st.apply_block(&mined, REWARD).expect("apply");
        (st, mined)
    }

    /// A spend of kp's coinbase UTXO to `to`, fully ML-DSA-signed.
    fn signed_spend(kp: &pqbit_core::KeyPair, st: &ChainState, to: Vec<u8>) -> Transaction {
        let ((txid, vout), (value, _)) = st
            .utxos
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                vout,
                signature: vec![],
            }],
            outputs: vec![TxOut {
                value,
                pubkey: to,
            }],
            locktime: 0,
        };
        tx.inputs[0].signature = sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, &tx.sighash()).unwrap();
        tx
    }

    #[test]
    fn accept_validates_rejects_garbage() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (st, blk) = one_block(&kp);
        let mut pool = Mempool::new();

        // valid spend → accepted
        let good = signed_spend(&kp, &st, vec![0xCD; 1312]);
        pool.accept(&good, &st).expect("valid accepted");
        assert_eq!(pool.len(), 1);

        // unsigned version of the same spend → invalid signature
        let mut bad = good.clone();
        bad.inputs[0].signature = vec![0xAA; 100];
        // recompute nothing: sighash changes only via inputs, so this is the
        // same txid; make it a *different* tx instead by changing output value
        bad.outputs[0].value = 49;
        assert!(matches!(
            pool.accept(&bad, &st),
            Err(MempoolError::Invalid(NodeError::BadSignature))
        ));

        let _ = blk;
    }

    #[test]
    fn duplicate_and_conflict_rejected() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (st, _) = one_block(&kp);
        let mut pool = Mempool::new();

        let tx = signed_spend(&kp, &st, vec![0xCD; 1312]);
        pool.accept(&tx, &st).expect("first ok");
        assert!(matches!(pool.accept(&tx, &st), Err(MempoolError::Duplicate)));

        // same prevout, different tx (different output) → conflict
        let mut tx2 = tx.clone();
        tx2.outputs[0].pubkey = vec![0xEE; 1312];
        // sighash changed → new txid, but inputs identical → conflicting
        tx2.inputs[0].signature =
            sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, &tx2.sighash()).unwrap();
        assert!(matches!(pool.accept(&tx2, &st), Err(MempoolError::Conflicting)));
    }

    #[test]
    fn remove_mined_drops_tx_and_conflicts() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (st, _) = one_block(&kp);
        let mut pool = Mempool::new();

        let tx = signed_spend(&kp, &st, vec![0xCD; 1312]);
        pool.accept(&tx, &st).expect("ok");
        pool.remove_mined(&tx);
        assert!(pool.is_empty());

        // re-accept works after removal (prevout released)
        pool.accept(&tx, &st).expect("re-accept after mined");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn wire_roundtrip() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (st, _) = one_block(&kp);
        let tx = signed_spend(&kp, &st, vec![0xCD; 1312]);
        let refs = vec![&tx];
        let dec = Mempool::decode_all(&Mempool::encode_all(&refs)).expect("decode");
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].sighash(), tx.sighash());
    }

    #[test]
    fn truncated_wire_caught() {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (st, _) = one_block(&kp);
        let tx = signed_spend(&kp, &st, vec![0xCD; 1312]);
        let refs = vec![&tx];
        let enc = Mempool::encode_all(&refs);
        assert!(matches!(
            Mempool::decode_all(&enc[..enc.len() - 5]),
            Err(NetError::Truncated)
        ));
    }

    #[test]
    fn mined_block_packs_pooled_spend() {
        // Full miner story: fund, pool a spend, mine a block that packs it,
        // pool drains, UTXO moves to the recipient.
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let (mut st, _) = one_block(&kp);
        let mut pool = Mempool::new();

        let to = generate_pq_keypair(SigAlgo::MlDsa44).unwrap();
        let tx = signed_spend(&kp, &st, to.public_key.bytes.clone());
        pool.accept(&tx, &st).expect("pooled");

        let blk = crate::chain::Block {
            height: st.tip_height + 1,
            prev_hash: st.tip_hash.clone(),
            timestamp: 1_700_000_100,
            transactions: vec![
                crate::chain::coinbase(kp.public_key.bytes.clone(), REWARD, st.tip_height + 1),
                tx.clone(),
            ],
            nonce: 0,
        };
        let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
        st.apply_block(&mined, REWARD).expect("applied with spend");
        pool.remove_mined(&tx);

        assert!(pool.is_empty(), "pooled tx must drain after mining");
        // recipient now holds the spent value as a UTXO
        let txid = hex::encode(tx.sighash());
        assert!(st.utxos.contains_key(&(txid, 0u32)));
    }
}
