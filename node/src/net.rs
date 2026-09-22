//! pqbit-node p2p layer (phase 3).
//!
//! Honest scope:
//!   1. length-prefixed framing (4-byte LE) with a hard 4 MiB cap,
//!   2. magic/version handshake so two nodes can greet each other,
//!   3. Ping/Pong liveness,
//!   4. full-block PULL sync: `GetBlocks(from_height)` → every block above it,
//!   5. addr manager: GETADDR/ADDR exchange + self-announcement, so a node
//!      that only knows one peer learns the rest of the mesh,
//!   6. push/pull GOSSIP rounds: a node taller than its peer pushes blocks,
//!      a node shorter than its peer pulls them — every block is PQ-validated
//!      before it touches our chain,
//!   7. mempool relay: TX / GETMEMPOOL / MEMPOOL — a gossip round also syncs
//!      the transaction pool (every tx ML-DSA-validated before admission),
//!   8. `mine_one`: mine a fresh block on the current tip packing pooled
//!      transactions — the primitive behind `serve --keep-mining`.
//!
//! Deliberately NOT here yet: persistent connections, unsolicited re-relay
//! (periodic rounds propagate instead — bounded traffic), NAT traversal,
//! reorg handling, fee policy. Boring, auditable, std-only.

#![allow(dead_code)]

use crate::chain::{coinbase, mine_block, Block, ChainState, NodeError};
use crate::mempool::Mempool;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Protocol magic: "PQBT".
pub const MAGIC: u32 = 0x5051_4254;
/// Wire protocol version (bump on breaking change).
pub const VERSION: u32 = 3;
/// Hard cap for a single framed message (4 MiB; a full PQ block is far below).
pub const MAX_MSG: usize = 4 * 1024 * 1024;
/// Per-read timeout; a silent peer gets dropped instead of pinned.
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Max entries an addr book will hold (mesh cap for v1).
pub const MAX_BOOK: usize = 512;
/// Max addrs accepted in one ADDR message.
pub const MAX_ADDR_MSG: usize = 1024;

pub const MSG_HANDSHAKE: u8 = 0x01;
pub const MSG_PING: u8 = 0x02;
pub const MSG_PONG: u8 = 0x03;
pub const MSG_GETBLOCKS: u8 = 0x04;
pub const MSG_BLOCKS: u8 = 0x05;
pub const MSG_GETADDR: u8 = 0x06;
pub const MSG_ADDR: u8 = 0x07;
pub const MSG_TX: u8 = 0x08;
pub const MSG_GETMEMPOOL: u8 = 0x09;
pub const MSG_MEMPOOL: u8 = 0x0A;

/// Errors the p2p layer can surface.
#[derive(Debug)]
pub enum NetError {
    Io(std::io::Error),
    /// Frame larger than MAX_MSG.
    TooLarge,
    /// Payload ended mid-field.
    Truncated,
    /// Peer magic mismatch.
    BadMagic,
    /// Message type byte we do not know.
    UnknownMsg(u8),
    /// Peer sent a block our chain rejected (PQ/PoW/chaining).
    BadBlock(NodeError),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io: {e}"),
            NetError::TooLarge => write!(f, "frame exceeds MAX_MSG"),
            NetError::Truncated => write!(f, "payload truncated mid-field"),
            NetError::BadMagic => write!(f, "peer magic mismatch"),
            NetError::UnknownMsg(k) => write!(f, "unknown message type 0x{k:02x}"),
            NetError::BadBlock(e) => write!(f, "peer sent invalid block: {e}"),
        }
    }
}
impl std::error::Error for NetError {}
impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

/// Read one length-prefixed frame (4-byte LE length + payload).
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, NetError> {
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)?;
    let len = u32::from_le_bytes(lenb) as usize;
    if len > MAX_MSG {
        return Err(NetError::TooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write one length-prefixed frame.
pub fn write_frame(w: &mut impl Write, data: &[u8]) -> Result<(), NetError> {
    if data.len() > MAX_MSG {
        return Err(NetError::TooLarge);
    }
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

/// A decoded wire message: 1 type byte + payload.
pub struct Message {
    pub kind: u8,
    pub payload: Vec<u8>,
}

pub fn read_message(r: &mut impl Read) -> Result<Message, NetError> {
    let buf = read_frame(r)?;
    if buf.is_empty() {
        return Err(NetError::Truncated);
    }
    Ok(Message {
        kind: buf[0],
        payload: buf[1..].to_vec(),
    })
}

pub fn write_message(w: &mut impl Write, kind: u8, payload: &[u8]) -> Result<(), NetError> {
    let mut buf = Vec::with_capacity(payload.len() + 1);
    buf.push(kind);
    buf.extend_from_slice(payload);
    write_frame(w, &buf)
}

// ---------------------------------------------------------------------------
// payload codecs (explicit, no serde: the wire format is the spec)
// ---------------------------------------------------------------------------

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
}

fn push_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn push_u64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn push_bytes(o: &mut Vec<u8>, v: &[u8]) {
    push_u32(o, v.len() as u32);
    o.extend_from_slice(v);
}

pub fn encode_handshake(magic: u32, version: u32, best_height: u64) -> Vec<u8> {
    let mut o = Vec::with_capacity(16);
    push_u32(&mut o, magic);
    push_u32(&mut o, version);
    push_u64(&mut o, best_height);
    o
}

/// (magic, version, best_height)
pub fn decode_handshake(p: &[u8]) -> Result<(u32, u32, u64), NetError> {
    let mut r = Reader::new(p);
    Ok((r.u32()?, r.u32()?, r.u64()?))
}

pub fn encode_u64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

pub fn decode_u64(p: &[u8]) -> Result<u64, NetError> {
    Reader::new(p).u64()
}

/// Canonical block encoding (matches `Block` field order, no compression).
pub fn encode_block(b: &Block) -> Vec<u8> {
    let mut o = Vec::new();
    push_u64(&mut o, b.height);
    push_u64(&mut o, b.timestamp);
    push_u64(&mut o, b.nonce);
    push_bytes(&mut o, b.prev_hash.as_bytes());
    push_u32(&mut o, b.transactions.len() as u32);
    for tx in &b.transactions {
        push_u32(&mut o, tx.version);
        push_u32(&mut o, tx.locktime);
        push_u32(&mut o, tx.inputs.len() as u32);
        for i in &tx.inputs {
            o.extend_from_slice(&i.prev_txid);
            push_u32(&mut o, i.vout);
            push_bytes(&mut o, &i.signature);
        }
        push_u32(&mut o, tx.outputs.len() as u32);
        for out in &tx.outputs {
            push_u64(&mut o, out.value);
            push_bytes(&mut o, &out.pubkey);
        }
    }
    o
}

pub fn decode_block(d: &[u8]) -> Result<Block, NetError> {
    read_block(&mut Reader::new(d))
}

fn read_block(r: &mut Reader<'_>) -> Result<Block, NetError> {
    let height = r.u64()?;
    let timestamp = r.u64()?;
    let nonce = r.u64()?;
    let prev_hash = String::from_utf8(r.bytes()?).map_err(|_| NetError::Truncated)?;
    let ntx = r.u32()? as usize;
    if ntx > MAX_MSG {
        return Err(NetError::TooLarge);
    }
    let mut transactions = Vec::with_capacity(ntx);
    for _ in 0..ntx {
        let version = r.u32()?;
        let locktime = r.u32()?;
        let nin = r.u32()? as usize;
        if nin > MAX_MSG {
            return Err(NetError::TooLarge);
        }
        let mut inputs = Vec::with_capacity(nin);
        for _ in 0..nin {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(r.take(32)?);
            let vout = r.u32()?;
            let signature = r.bytes()?;
            inputs.push(pqbit_core::TxIn {
                prev_txid,
                vout,
                signature,
            });
        }
        let nout = r.u32()? as usize;
        if nout > MAX_MSG {
            return Err(NetError::TooLarge);
        }
        let mut outputs = Vec::with_capacity(nout);
        for _ in 0..nout {
            let value = r.u64()?;
            let pubkey = r.bytes()?;
            outputs.push(pqbit_core::TxOut { value, pubkey });
        }
        transactions.push(pqbit_core::Transaction {
            version,
            inputs,
            outputs,
            locktime,
        });
    }
    Ok(Block {
        height,
        prev_hash,
        timestamp,
        transactions,
        nonce,
    })
}

pub fn encode_blocks(blocks: &[Block]) -> Vec<u8> {
    let mut o = Vec::new();
    push_u32(&mut o, blocks.len() as u32);
    for b in blocks {
        o.extend_from_slice(&encode_block(b));
    }
    o
}

pub fn decode_blocks(p: &[u8]) -> Result<Vec<Block>, NetError> {
    let mut r = Reader::new(p);
    let n = r.u32()? as usize;
    if n > MAX_MSG {
        return Err(NetError::TooLarge);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(read_block(&mut r)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// addr codec
// ---------------------------------------------------------------------------

/// ADDR payload: u32 count + count × length-prefixed "ip:port" strings.
pub fn encode_addrs(addrs: &[String]) -> Vec<u8> {
    let mut o = Vec::new();
    push_u32(&mut o, addrs.len() as u32);
    for a in addrs {
        push_bytes(&mut o, a.as_bytes());
    }
    o
}

pub fn decode_addrs(p: &[u8]) -> Result<Vec<String>, NetError> {
    let mut r = Reader::new(p);
    let n = r.u32()? as usize;
    if n > MAX_ADDR_MSG {
        return Err(NetError::TooLarge);
    }
    let mut out = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        let s = String::from_utf8(r.bytes()?).map_err(|_| NetError::Truncated)?;
        out.push(s);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// addr book
// ---------------------------------------------------------------------------

/// Peer address book: addr → last-seen (UNIX secs). Self-announcement plus
/// GETADDR gossip makes a one-seed node discover the rest of the mesh.
///
/// PERSISTENT PEER STORE (Q1 milestone): when built `with_persistence`, the
/// book survives restarts. Plain-text file, one `last_seen addr` per line —
/// no serde, per repo rules. Writes are atomic (tmp + rename) and flushed
/// after every merge batch (and on drop); a corrupt or missing file loads as
/// an empty book — the mesh re-discovers peers anyway, so fail-open is safe.
#[derive(Default)]
pub struct AddrBook {
    map: HashMap<String, u64>,
    persist_path: Option<PathBuf>,
    dirty: bool,
}

impl AddrBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// In-memory book that loads (and later flushes to) `path`.
    pub fn with_persistence(path: &Path) -> Self {
        let mut book = Self {
            map: HashMap::new(),
            persist_path: Some(path.to_path_buf()),
            dirty: false,
        };
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                for line in raw.lines() {
                    let mut parts = line.splitn(2, ' ');
                    let (seen, addr) = match (parts.next(), parts.next()) {
                        (Some(s), Some(a)) if !a.is_empty() => (s, a),
                        _ => continue, // junk line: skip, don't poison the book
                    };
                    let seen: u64 = match seen.parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if Self::addr_sane(addr) && book.map.len() < MAX_BOOK {
                        book.map.insert(addr.to_string(), seen);
                    }
                }
            }
            // missing file = first run; unreadable = warn but continue (mesh
            // re-discovers peers, so an empty book is never fatal)
            Err(e) if e.kind() != ErrorKind::NotFound => {
                eprintln!("pqbit-net: peer store unreadable ({}): {e}", path.display());
            }
            Err(_) => {}
        }
        book
    }

    fn addr_sane(addr: &str) -> bool {
        !addr.is_empty()
            && addr.len() <= 64
            && !addr.contains(char::is_whitespace)
            && addr.contains(':')
    }

    /// Merge one addr. Returns true if it was new. Rejects junk and, when the
    /// book is full, unknown addrs (known ones just get their last-seen bumped).
    pub fn merge(&mut self, addr: &str, now: u64) -> bool {
        if !Self::addr_sane(addr) {
            return false;
        }
        if let Some(seen) = self.map.get_mut(addr) {
            *seen = now;
            self.dirty = true;
            return false;
        }
        if self.map.len() >= MAX_BOOK {
            return false;
        }
        self.map.insert(addr.to_string(), now);
        self.dirty = true;
        true
    }

    /// Write the book to disk if it changed. Atomic: tmp file + rename.
    pub fn flush(&mut self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        if !self.dirty {
            return;
        }
        let mut body = String::with_capacity(self.map.len() * 32);
        for (addr, seen) in &self.map {
            body.push_str(&seen.to_string());
            body.push(' ');
            body.push_str(addr);
            body.push('\n');
        }
        let tmp = path.with_extension("txt.tmp");
        if std::fs::write(&tmp, body)
            .and_then(|_| std::fs::rename(&tmp, path))
            .is_ok()
        {
            self.dirty = false;
        }
    }

    pub fn addrs(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Drop for AddrBook {
    fn drop(&mut self) {
        self.flush();
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// node state
// ---------------------------------------------------------------------------

/// Everything a connection handler or gossip round needs. All shared state is
/// behind Arc<Mutex<…>> so inbound threads and the gossiper see one node.
#[derive(Clone)]
pub struct NodeState {
    /// The addr we advertise to peers ("ip:port" they can dial back).
    pub listen: String,
    /// Coinbase reward cap (validation parameter).
    pub reward: u64,
    /// Append-only validated block store.
    pub blocks: Arc<Mutex<Vec<Block>>>,
    /// The authoritative chain state (UTXO set + tip).
    pub chain: Arc<Mutex<ChainState>>,
    /// Known peer addresses.
    pub book: Arc<Mutex<AddrBook>>,
    /// Unconfirmed transaction pool.
    pub pool: Arc<Mutex<Mempool>>,
    /// Coinbase paying key (mining + announce identity).
    pub miner_key: Arc<Vec<u8>>,
}

impl NodeState {
    pub fn best_height(&self) -> u64 {
        self.chain.lock().expect("chain poisoned").tip_height
    }

    /// Store a block that does not extend our tip (a fork sibling). These are
    /// kept so a longest-chain switch can re-apply them later without a re-fetch.
    fn stash_block(&self, b: &Block) {
        let mut store = self.blocks.lock().expect("store poisoned");
        if !store.iter().any(|x| x.hash() == b.hash()) {
            store.push(b.clone());
        }
    }

    /// Validate + apply one incoming block.
    ///
    /// Fork choice (v1, honest): a block is applied when it extends our tip.
    /// A sibling at the same height is stashed. A block TALLER than our tip
    /// by more than 1 triggers a REORG: we roll our chain back to the fork
    /// point and re-apply the incoming branch — standard longest-chain rule.
    /// The UTXO set is rebuilt by replaying blocks (no undo log yet: honest,
    /// simple, correct; the store is small on testnet).
    pub fn apply_incoming(&self, incoming: &Block) -> Result<(), NetError> {
        let mut chain = self.chain.lock().expect("chain poisoned");
        if incoming.height <= chain.tip_height {
            // same height, different hash → fork sibling: stash it
            if incoming.height == chain.tip_height && incoming.hash() != chain.tip_hash {
                drop(chain);
                self.stash_block(incoming);
            }
            return Ok(());
        }
        if incoming.prev_hash == chain.tip_hash {
            // clean extension
            chain
                .apply_block(incoming, self.reward)
                .map_err(NetError::BadBlock)?;
            drop(chain);
            self.blocks
                .lock()
                .expect("store poisoned")
                .push(incoming.clone());
            return Ok(());
        }
        // Taller but not chaining on our tip → possible reorg. Longest-chain
        // rule, v1: the incoming branch must already be fully known in our
        // store (stashed earlier, chained back to genesis). If so, it is
        // STRICTLY LONGER than our tip (height > tip_height) → reorg.
        drop(chain);
        let store = self.blocks.lock().expect("store poisoned");
        let mut branch: Vec<Block> = vec![incoming.clone()];
        let mut complete = false;
        loop {
            let tip_prev = branch.last().unwrap().prev_hash.clone();
            if tip_prev.is_empty() {
                complete = true; // chained back to genesis
                break;
            }
            match store.iter().find(|b| b.hash() == tip_prev) {
                Some(prev) => branch.push(prev.clone()),
                None => break, // missing ancestor: cannot reorg yet (stash & wait)
            }
        }
        if !complete {
            drop(store);
            self.stash_block(incoming);
            return Ok(());
        }
        drop(store);
        // REORG: replay the incoming branch from genesis with OUR difficulty
        let difficulty = {
            let chain = self.chain.lock().expect("chain poisoned");
            chain.difficulty
        };
        let mut fresh = ChainState::new(difficulty);
        let mut ordered = branch.clone();
        ordered.reverse(); // genesis-side first
        for b in &ordered {
            fresh
                .apply_block(b, self.reward)
                .map_err(NetError::BadBlock)?;
        }
        // txs from orphaned blocks return to the mempool (best effort)
        let new_hashes: Vec<String> = ordered.iter().map(|b| b.hash()).collect();
        let orphaned_txs: Vec<pqbit_core::Transaction> = {
            let store = self.blocks.lock().expect("store poisoned");
            store
                .iter()
                .filter(|b| b.height > 0 && !new_hashes.contains(&b.hash()))
                .flat_map(|b| b.transactions.iter().skip(1).cloned())
                .collect()
        };
        {
            let mut pool = self.pool.lock().expect("pool poisoned");
            for tx in &orphaned_txs {
                let _ = pool.accept(tx, &fresh);
            }
        }
        {
            let mut store = self.blocks.lock().expect("store poisoned");
            *store = ordered;
        }
        {
            let mut chain = self.chain.lock().expect("chain poisoned");
            *chain = fresh;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// connection handler
// ---------------------------------------------------------------------------

/// Serve one connection: handshake, then answer Ping / GetBlocks / GetAddr,
/// merge announced addrs, and accept pushed blocks (validated) until EOF.
pub fn handle_conn(mut stream: TcpStream, state: &NodeState) -> Result<(), NetError> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let m = read_message(&mut stream)?;
    if m.kind != MSG_HANDSHAKE {
        return Err(NetError::UnknownMsg(m.kind));
    }
    let (magic, _version, _their_height) = decode_handshake(&m.payload)?;
    if magic != MAGIC {
        return Err(NetError::BadMagic);
    }
    write_message(
        &mut stream,
        MSG_HANDSHAKE,
        &encode_handshake(MAGIC, VERSION, state.best_height()),
    )?;

    loop {
        let m = match read_message(&mut stream) {
            Ok(m) => m,
            Err(NetError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(NetError::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                return Ok(()); // silent peer: close politely
            }
            Err(e) => return Err(e),
        };
        match m.kind {
            MSG_PING => {
                let n = decode_u64(&m.payload)?;
                write_message(&mut stream, MSG_PONG, &encode_u64(n))?;
            }
            MSG_GETBLOCKS => {
                let from = decode_u64(&m.payload)?;
                let store = state.blocks.lock().expect("store poisoned");
                let reply: Vec<Block> = store.iter().filter(|b| b.height > from).cloned().collect();
                drop(store);
                write_message(&mut stream, MSG_BLOCKS, &encode_blocks(&reply))?;
            }
            MSG_GETADDR => {
                let addrs = state.book.lock().expect("book poisoned").addrs();
                write_message(&mut stream, MSG_ADDR, &encode_addrs(&addrs))?;
            }
            MSG_ADDR => {
                let addrs = decode_addrs(&m.payload)?;
                let mut book = state.book.lock().expect("book poisoned");
                let now = now_unix();
                for a in addrs {
                    if a == state.listen {
                        continue; // never gossip ourselves to ourselves
                    }
                    book.merge(&a, now);
                }
                book.flush(); // learned addrs survive a restart
            }
            MSG_BLOCKS => {
                // Unsolicited push from a taller peer. Validate every block;
                // one bad block and we drop the connection (misbehaving peer).
                let blocks = decode_blocks(&m.payload)?;
                for b in &blocks {
                    state.apply_incoming(b)?;
                }
            }
            MSG_TX => {
                let txs = Mempool::decode_all(&m.payload)?;
                let mut pool = state.pool.lock().expect("pool poisoned");
                let chain = state.chain.lock().expect("chain poisoned");
                for tx in &txs {
                    // admission errors are fine: duplicates/conflicts happen
                    // in every healthy network; a *signature* failure here is
                    // also not fatal for the connection (tx-level rejection).
                    let _ = pool.accept(tx, &chain);
                }
            }
            MSG_GETMEMPOOL => {
                let payload = {
                    let pool = state.pool.lock().expect("pool poisoned");
                    Mempool::encode_all(&pool.txs())
                };
                write_message(&mut stream, MSG_MEMPOOL, &payload)?;
            }
            other => return Err(NetError::UnknownMsg(other)),
        }
    }
}

/// Bind + accept loop (one thread per connection).
pub fn serve(listener: TcpListener, state: NodeState) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state = state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(s, &state) {
                        eprintln!("pqbit-net: peer dropped: {e}");
                    }
                });
            }
            Err(e) => eprintln!("pqbit-net: accept error: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// gossip (client side)
// ---------------------------------------------------------------------------

/// What one gossip round achieved.
#[derive(Debug, Default, PartialEq)]
pub struct GossipRound {
    pub their_height: u64,
    /// Blocks we pulled and applied (peer was taller).
    pub pulled: usize,
    /// Blocks we pushed (we were taller).
    pub pushed: usize,
    /// New addresses learned from the peer's book.
    pub learned: usize,
    /// New transactions admitted into our pool from the peer.
    pub txs: usize,
}

/// One connect-sync-disconnect round against `peer`:
/// handshake → self-announce → GETADDR → pull or push, depending on heights.
pub fn gossip_round(peer: &str, state: &NodeState) -> Result<GossipRound, NetError> {
    let mut s = TcpStream::connect(peer)?;
    s.set_read_timeout(Some(READ_TIMEOUT))?;

    let our_height = state.best_height();
    write_message(
        &mut s,
        MSG_HANDSHAKE,
        &encode_handshake(MAGIC, VERSION, our_height),
    )?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_HANDSHAKE {
        return Err(NetError::UnknownMsg(m.kind));
    }
    let (magic, _v, their_height) = decode_handshake(&m.payload)?;
    if magic != MAGIC {
        return Err(NetError::BadMagic);
    }
    let mut round = GossipRound {
        their_height,
        ..Default::default()
    };

    // we just talked to this peer: bump its freshness so the persistent
    // store keeps dialable, recently-alive addrs (and flushes the bump)
    {
        let mut book = state.book.lock().expect("book poisoned");
        book.merge(peer, now_unix());
        book.flush();
    }

    // 1. announce ourselves so the peer's book grows (mesh formation)
    let announce = [state.listen.clone()];
    write_message(&mut s, MSG_ADDR, &encode_addrs(&announce))?;
    // 2. ask for their book
    write_message(&mut s, MSG_GETADDR, &[])?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_ADDR {
        return Err(NetError::UnknownMsg(m.kind));
    }
    {
        let mut book = state.book.lock().expect("book poisoned");
        let now = now_unix();
        for a in decode_addrs(&m.payload)? {
            if a == state.listen {
                continue;
            }
            if book.merge(&a, now) {
                round.learned += 1;
            }
        }
        book.flush(); // learned addrs survive a restart
    }

    // 3. sync blocks FIRST: a tx can only validate against a UTXO set that
    // already contains its prevout, so chain sync precedes mempool relay.
    if their_height > our_height {
        write_message(&mut s, MSG_GETBLOCKS, &encode_u64(our_height))?;
        let m = read_message(&mut s)?;
        if m.kind != MSG_BLOCKS {
            return Err(NetError::UnknownMsg(m.kind));
        }
        let blocks = decode_blocks(&m.payload)?;
        for b in &blocks {
            state.apply_incoming(b)?;
            round.pulled += 1;
        }
    } else if our_height > their_height {
        let blocks: Vec<Block> = {
            let store = state.blocks.lock().expect("store poisoned");
            store
                .iter()
                .filter(|b| b.height > their_height)
                .cloned()
                .collect()
        };
        if !blocks.is_empty() {
            write_message(&mut s, MSG_BLOCKS, &encode_blocks(&blocks))?;
            round.pushed = blocks.len();
        }
    }

    // 4. mempool relay: broadcast ours, fetch theirs (every tx validated on
    // admission; duplicates/conflicts are normal noise, not errors)
    let ours_payload = {
        let pool = state.pool.lock().expect("pool poisoned");
        Mempool::encode_all(&pool.txs())
    };
    write_message(&mut s, MSG_TX, &ours_payload)?;
    write_message(&mut s, MSG_GETMEMPOOL, &[])?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_MEMPOOL {
        return Err(NetError::UnknownMsg(m.kind));
    }
    {
        let mut pool = state.pool.lock().expect("pool poisoned");
        let chain = state.chain.lock().expect("chain poisoned");
        for tx in Mempool::decode_all(&m.payload)? {
            if pool.accept(&tx, &chain).is_ok() {
                round.txs += 1;
            }
        }
    }

    Ok(round)
}

/// Background gossip loop: periodic rounds to every known peer (seeds first,
/// then anything learned along the way). Runs until `stop` is set.
pub fn gossiper_loop(
    seeds: Vec<String>,
    state: NodeState,
    interval: Duration,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let mut targets: Vec<String> = seeds.clone();
        targets.extend(state.book.lock().expect("book poisoned").addrs());
        targets.sort();
        targets.dedup();
        // bound work per round: at most 8 peers per tick
        for peer in targets.into_iter().take(8) {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match gossip_round(&peer, &state) {
                Ok(r) => {
                    if r.pulled > 0 || r.pushed > 0 || r.learned > 0 || r.txs > 0 {
                        eprintln!(
                            "pqbit-net: gossip {peer}: +{} pulled, {} pushed, {} addrs, +{} txs (their tip {})",
                            r.pulled, r.pushed, r.learned, r.txs, r.their_height
                        );
                    }
                }
                Err(e) => eprintln!("pqbit-net: gossip {peer} failed: {e}"),
                // (success log handled above)
            }
        }
        std::thread::sleep(interval);
    }
}

// ---------------------------------------------------------------------------
// mining
// ---------------------------------------------------------------------------

/// Mine one block on the current tip, packing every pooled transaction
/// (coinbase first). On success the pool is drained of the mined txs.
/// Returns the mined block. This is the primitive behind `--keep-mining`:
/// founder and everyone else mine by the same rules after genesis.
pub fn mine_one(state: &NodeState, difficulty: u32, max_nonce: u64) -> Result<Block, NetError> {
    // Snapshot the template under a SHORT lock — the PoW loop itself runs
    // lock-free so network handling is never starved by mining.
    let (tip_height, tip_hash, txs) = {
        let chain = state.chain.lock().expect("chain poisoned");
        let txs: Vec<pqbit_core::Transaction> = state
            .pool
            .lock()
            .expect("pool poisoned")
            .txs()
            .into_iter()
            .cloned()
            .collect();
        (chain.tip_height, chain.tip_hash.clone(), txs)
    };
    let blk = Block {
        height: tip_height + 1,
        prev_hash: tip_hash,
        timestamp: now_unix(),
        transactions: {
            let mut v = Vec::with_capacity(txs.len() + 1);
            v.push(coinbase(
                (*state.miner_key).clone(),
                state.reward,
                tip_height + 1,
            ));
            v.extend(txs);
            v
        },
        nonce: 0,
    };
    let mined = mine_block(blk, difficulty, max_nonce).ok_or(NetError::Io(
        std::io::Error::other("mining budget exhausted"),
    ))?;
    // Re-validate under the lock: the tip may have moved while we mined
    // (a peer block won the race) — then our block is simply stale, drop it.
    let mut chain = state.chain.lock().expect("chain poisoned");
    if chain.tip_height + 1 != mined.height || chain.tip_hash != mined.prev_hash {
        return Err(NetError::Io(std::io::Error::other(
            "stale block: tip moved while mining",
        )));
    }
    chain
        .apply_block(&mined, state.reward)
        .map_err(NetError::BadBlock)?;
    state
        .blocks
        .lock()
        .expect("store poisoned")
        .push(mined.clone());
    state
        .pool
        .lock()
        .expect("pool poisoned")
        .remove_mined_txs(&mined);
    Ok(mined)
}

// ---------------------------------------------------------------------------
// one-shot pull (kept as a primitive for a future `sync` subcommand)
// ---------------------------------------------------------------------------

/// One-shot client: connect, handshake, pull blocks above `from_height`.
/// Returns (their best height, blocks).
pub fn pull_blocks(addr: &str, from_height: u64) -> Result<(u64, Vec<Block>), NetError> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(READ_TIMEOUT))?;
    write_message(
        &mut s,
        MSG_HANDSHAKE,
        &encode_handshake(MAGIC, VERSION, from_height),
    )?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_HANDSHAKE {
        return Err(NetError::UnknownMsg(m.kind));
    }
    let (magic, _v, their_height) = decode_handshake(&m.payload)?;
    if magic != MAGIC {
        return Err(NetError::BadMagic);
    }
    if their_height <= from_height {
        return Ok((their_height, Vec::new()));
    }
    write_message(&mut s, MSG_GETBLOCKS, &encode_u64(from_height))?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_BLOCKS {
        return Err(NetError::UnknownMsg(m.kind));
    }
    Ok((their_height, decode_blocks(&m.payload)?))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pqbit_core::{generate_pq_keypair, SigAlgo, Transaction, TxOut};

    const D: u32 = 8;
    const REWARD: u64 = 50;

    fn fake_block(height: u64, prev: &str) -> Block {
        Block {
            height,
            prev_hash: prev.to_string(),
            timestamp: 1_700_000_000 + height,
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOut {
                    value: 50_000_000,
                    pubkey: vec![0xAB; 1312], // ML-DSA-44 pk size
                }],
                locktime: 0,
            }],
            nonce: height * 7,
        }
    }

    /// Mine a real `n`-block chain (PQ coinbase, real PoW) and return
    /// (ChainState, blocks).
    fn mined_chain(n: u64) -> (ChainState, Vec<Block>) {
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let mut st = ChainState::new(D);
        let mut blocks = Vec::new();
        for h in 1..=n {
            let blk = Block {
                height: st.tip_height + 1,
                prev_hash: st.tip_hash.clone(),
                timestamp: 1_700_000_000 + h,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    st.tip_height + 1,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st.apply_block(&mined, REWARD).expect("apply");
            blocks.push(mined);
        }
        (st, blocks)
    }

    fn node_with(chain: ChainState, blocks: Vec<Block>, listen: &str) -> NodeState {
        NodeState {
            listen: listen.to_string(),
            reward: REWARD,
            blocks: Arc::new(Mutex::new(blocks)),
            chain: Arc::new(Mutex::new(chain)),
            book: Arc::new(Mutex::new(AddrBook::new())),
            pool: Arc::new(Mutex::new(Mempool::new())),
            miner_key: Arc::new(vec![0xAB; 1312]),
        }
    }

    /// Spawn a one-connection server for `state` and return its dial address.
    fn spawn_server(state: NodeState) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            let _ = handle_conn(s, &state);
        });
        addr
    }

    #[test]
    fn block_codec_roundtrip() {
        let b = fake_block(7, "deadbeef");
        let enc = encode_block(&b);
        let dec = decode_block(&enc).expect("decode");
        assert_eq!(dec.height, b.height);
        assert_eq!(dec.prev_hash, b.prev_hash);
        assert_eq!(dec.timestamp, b.timestamp);
        assert_eq!(dec.nonce, b.nonce);
        assert_eq!(dec.transactions.len(), 1);
        assert_eq!(dec.transactions[0].outputs[0].pubkey, vec![0xAB; 1312]);
    }

    #[test]
    fn blocks_roundtrip_many() {
        let blocks: Vec<Block> = (0..5).map(|i| fake_block(i, "aa")).collect();
        let dec = decode_blocks(&encode_blocks(&blocks)).expect("decode many");
        assert_eq!(dec.len(), 5);
        assert_eq!(dec[3].nonce, 21);
    }

    #[test]
    fn truncated_payload_is_caught() {
        let enc = encode_block(&fake_block(1, "ff"));
        assert!(matches!(
            decode_block(&enc[..enc.len() - 3]),
            Err(NetError::Truncated)
        ));
    }

    #[test]
    fn addr_codec_and_book() {
        let addrs = vec!["10.0.0.1:18444".to_string(), "[::1]:18445".to_string()];
        let dec = decode_addrs(&encode_addrs(&addrs)).expect("decode addrs");
        assert_eq!(dec, addrs);

        let mut book = AddrBook::new();
        assert!(book.merge("1.2.3.4:1", 100));
        assert!(!book.merge("1.2.3.4:1", 200), "dup is not new");
        assert!(!book.merge("", 1), "empty rejected");
        assert!(!book.merge("no port", 1), "needs a colon");
        assert!(!book.merge("1.2.3.4:1 with space", 1));
        assert_eq!(book.len(), 1);
        assert_eq!(book.addrs(), vec!["1.2.3.4:1".to_string()]);
    }

    #[test]
    fn peer_store_survives_restart() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("pqbit-peers-test-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // "session 1": learn two peers, flush, drop
        {
            let mut book = AddrBook::with_persistence(&path);
            assert!(book.is_empty(), "fresh file = empty book");
            assert!(book.merge("10.0.0.9:18444", 1_000));
            assert!(book.merge("10.0.0.8:18445", 2_000));
            assert!(
                !book.merge("10.0.0.8:18445", 2_500),
                "known addr bumps, not adds"
            );
            book.flush();
        }

        // "session 2": a new process loads what session 1 learned
        {
            let book = AddrBook::with_persistence(&path);
            assert_eq!(book.len(), 2, "both peers survive the restart");
            assert!(book.addrs().contains(&"10.0.0.9:18444".to_string()));
            assert!(book.addrs().contains(&"10.0.0.8:18445".to_string()));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn peer_store_rejects_junk_and_renders_garbage_harmless() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("pqbit-peers-junk-{}.txt", std::process::id()));
        // corrupt file: junk lines, missing timestamps, insane addrs, valid line
        std::fs::write(
            &path,
            "not a peer line\n9999 bad addr with spaces\n\nabc:1\n777 10.1.1.1:18444\n",
        )
        .expect("write junk store");
        let book = AddrBook::with_persistence(&path);
        assert_eq!(book.len(), 1, "only the valid line survives");
        assert!(book.addrs().contains(&"10.1.1.1:18444".to_string()));
        let _ = std::fs::remove_file(&path);

        // missing parent dir: load is empty, flush fails silently, node keeps running
        let mut book = AddrBook::with_persistence(Path::new("/nonexistent-dir-peers/x.txt"));
        assert!(book.is_empty());
        assert!(book.merge("10.9.9.9:1", 5));
        book.flush(); // must not panic even though the write fails
    }

    #[test]
    fn peer_store_in_memory_book_never_writes() {
        // default book (no persistence) must stay exactly that: no file I/O
        let mut book = AddrBook::new();
        assert!(book.merge("1.1.1.1:1", 1));
        book.flush(); // no-op without a persist path
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn end_to_end_sync_two_nodes() {
        // node A: a real 2-block chain mined with the actual PQ miner
        let (st, store) = mined_chain(2);
        let tip = st.tip_hash.clone();
        let a = node_with(st, store, "127.0.0.1:1");

        let addr = spawn_server(a.clone());

        // node B: fresh, pulls everything, applies, reaches the same tip
        let (their_height, blocks) = pull_blocks(&addr, 0).expect("pull");
        assert_eq!(their_height, 2);
        assert_eq!(blocks.len(), 2);
        let mut st_b = ChainState::new(D);
        for b in &blocks {
            st_b.apply_block(b, REWARD).expect("B applies valid block");
        }
        assert_eq!(st_b.tip_hash, tip, "B must land on A's tip");
        assert_eq!(st_b.total_supply, 100); // 2 × 50
    }

    #[test]
    fn gossip_push_updates_shorter_peer() {
        // A has 2 blocks, B is empty. A runs a gossip round against B:
        // B must learn A's addr (announcement) and receive both blocks (push),
        // validated through the full PQ chain.
        let (st_a, blocks_a) = mined_chain(2);
        let tip_a = st_a.tip_hash.clone();
        let a = node_with(st_a, blocks_a, "10.0.0.9:18444");

        let (st_b, empty) = (ChainState::new(D), Vec::new());
        let b = node_with(st_b, empty, "10.0.0.8:18444");

        let addr_b = spawn_server(b.clone());

        let r = gossip_round(&addr_b, &a).expect("gossip round");
        assert_eq!(r.pushed, 2, "A pushes both blocks");
        assert_eq!(r.pulled, 0);
        assert_eq!(r.their_height, 0);

        // Push is fire-and-forget: the server applies async. Wait (bounded)
        // for B to converge.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while b.best_height() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }

        // B applied and validated: same tip, same supply
        assert_eq!(b.best_height(), 2);
        assert_eq!(b.chain.lock().unwrap().tip_hash, tip_a);
        assert_eq!(b.chain.lock().unwrap().total_supply, 100);
        assert_eq!(b.blocks.lock().unwrap().len(), 2);

        // B's book grew with A's announced addr
        assert!(b
            .book
            .lock()
            .unwrap()
            .addrs()
            .contains(&"10.0.0.9:18444".to_string()));
    }

    #[test]
    fn gossip_pull_by_shorter_client() {
        // Tall B serves; empty C dials B as a client: C must pull all 3 blocks
        // (client was shorter) and land on B's tip.
        let (st_b, blocks_b) = mined_chain(3);
        let tip_b = st_b.tip_hash.clone();
        let b = node_with(st_b, blocks_b, "10.0.0.7:18444");
        let addr_b = spawn_server(b.clone());

        let c = node_with(ChainState::new(D), Vec::new(), "10.0.0.6:18444");
        let r = gossip_round(&addr_b, &c).expect("gossip round");
        assert_eq!(r.pulled, 3);
        assert_eq!(r.pushed, 0);
        assert_eq!(r.their_height, 3);
        assert_eq!(c.best_height(), 3);
        assert_eq!(c.chain.lock().unwrap().tip_hash, tip_b);
    }

    #[test]
    fn addr_propagation_via_getaddr() {
        // B already knows A. C dials B: C must learn A's addr from B's book
        // (GETADDR), and B must learn C's addr (C's announcement).
        let (st, empty) = (ChainState::new(D), Vec::<Block>::new());
        let a = node_with(st, empty, "10.0.0.1:18444"); // only referenced by addr
        let a_addr = a.listen.clone();

        let b = node_with(ChainState::new(D), Vec::new(), "10.0.0.2:18444");
        b.book.lock().unwrap().merge(&a_addr, now_unix());
        let addr_b = spawn_server(b.clone());

        let c = node_with(ChainState::new(D), Vec::new(), "10.0.0.3:18444");
        let r = gossip_round(&addr_b, &c).expect("round C→B");
        assert_eq!(r.learned, 1, "C learns exactly A");
        assert!(c.book.lock().unwrap().addrs().contains(&a_addr));
        assert!(b
            .book
            .lock()
            .unwrap()
            .addrs()
            .contains(&"10.0.0.3:18444".to_string()));
    }

    #[test]
    fn gossiper_loop_converges_two_nodes() {
        // A serves continuously; B's gossiper loop (seeds = [A]) must pull
        // A's chain until the tips match, then stay quiet.
        let (st_a, blocks_a) = mined_chain(2);
        let tip_a = st_a.tip_hash.clone();
        let a = node_with(st_a, blocks_a, "127.0.0.1:2");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr_a = listener.local_addr().expect("addr").to_string();
        let a_srv = a.clone();
        std::thread::spawn(move || {
            // multiple rounds will dial: serve until process ends
            for s in listener.incoming() {
                let st = a_srv.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(s.expect("sock"), &st);
                });
            }
        });

        let b = node_with(ChainState::new(D), Vec::new(), "127.0.0.1:3");
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let b2 = b.clone();
        let seeds = vec![addr_a.clone()];
        let handle = std::thread::spawn(move || {
            gossiper_loop(seeds, b2, Duration::from_millis(25), stop2);
        });

        // wait (bounded) for convergence
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while b.best_height() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();

        assert_eq!(b.best_height(), 2, "gossiper loop must converge to A's tip");
        assert_eq!(b.chain.lock().unwrap().tip_hash, tip_a);
    }

    #[test]
    fn mempool_relays_over_wire() {
        // A mines a chain with a KNOWN key, pools a signed spend, then runs a
        // gossip round against empty B. B's pool must end up holding the tx.
        use pqbit_core::{sign_pq, TxIn, TxOut};

        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let (st_a, blocks_a) = {
            let mut st = ChainState::new(D);
            let blk = Block {
                height: 1,
                prev_hash: String::new(),
                timestamp: 1_700_000_000,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    1,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st.apply_block(&mined, REWARD).expect("apply");
            (st, vec![mined])
        };
        let a = node_with(st_a, blocks_a, "10.0.0.11:18444");

        // signed spend of the coinbase UTXO
        let ((txid, vout), (value, _)) = a
            .chain
            .lock()
            .unwrap()
            .utxos
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let mut tx = pqbit_core::Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                vout,
                signature: vec![],
            }],
            outputs: vec![TxOut {
                value,
                pubkey: vec![0xEE; 1312],
            }],
            locktime: 0,
        };
        tx.inputs[0].signature =
            sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, &tx.sighash()).expect("sign");
        a.pool
            .lock()
            .unwrap()
            .accept(&tx, &a.chain.lock().unwrap())
            .expect("pool A");

        let b = node_with(ChainState::new(D), Vec::new(), "10.0.0.12:18444");
        let addr_b = spawn_server(b.clone());

        let r = gossip_round(&addr_b, &a).expect("round");
        assert_eq!(r.pushed, 1, "A is taller: pushes its block");

        // Push is fire-and-forget: B's handler applies the block and admits
        // the relayed txs async. Wait (bounded) for both to land.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while (b.best_height() < 1 || b.pool.lock().unwrap().is_empty())
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(b.best_height(), 1, "B applied the pushed block");
        assert_eq!(b.pool.lock().unwrap().len(), 1, "tx relayed over wire");
    }

    #[test]
    fn mine_one_packs_pool_and_drains() {
        // Known-key chain, one pooled spend → mine_one must produce a block
        // containing coinbase + spend, apply it, and drain the pool.
        use pqbit_core::{sign_pq, TxIn, TxOut};

        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let (st, blocks) = {
            let mut st = ChainState::new(D);
            let blk = Block {
                height: 1,
                prev_hash: String::new(),
                timestamp: 1_700_000_000,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    1,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st.apply_block(&mined, REWARD).expect("apply");
            (st, vec![mined])
        };
        let mut n = node_with(st, blocks, "10.0.0.13:18444");
        n.miner_key = Arc::new(kp.public_key.bytes.clone());

        let ((txid, vout), (value, _)) = n
            .chain
            .lock()
            .unwrap()
            .utxos
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let mut tx = pqbit_core::Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: hex::decode(&txid).unwrap().try_into().unwrap(),
                vout,
                signature: vec![],
            }],
            outputs: vec![TxOut {
                value,
                pubkey: vec![0x77; 1312],
            }],
            locktime: 0,
        };
        tx.inputs[0].signature =
            sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, &tx.sighash()).expect("sign");
        n.pool
            .lock()
            .unwrap()
            .accept(&tx, &n.chain.lock().unwrap())
            .expect("pool");

        let blk = mine_one(&n, D, 2_000_000).expect("mine_one");
        assert_eq!(blk.transactions.len(), 2, "coinbase + pooled spend");
        assert_eq!(n.best_height(), 2);
        assert!(
            n.pool.lock().unwrap().is_empty(),
            "pool drained after mining"
        );
    }

    #[test]
    fn reorg_to_longer_fork_branch() {
        // Two miners build different blocks at height 2 (fork). The fork with
        // MORE work (height 3) wins: node must reorg and orphan our block 2.
        use pqbit_core::{generate_pq_keypair, SigAlgo};
        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");

        // common ancestor: block 1
        let mut st0 = ChainState::new(D);
        let b1 = {
            let blk = Block {
                height: 1,
                prev_hash: String::new(),
                timestamp: 1_700_000_000,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    1,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st0.apply_block(&mined, REWARD).expect("apply");
            mined
        };

        // our branch: block 2A on top of block 1
        let mut st_a = st0.clone();
        let b2a = {
            let blk = Block {
                height: 2,
                prev_hash: st_a.tip_hash.clone(),
                timestamp: 1_700_000_100,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    2,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st_a.apply_block(&mined, REWARD).expect("apply");
            mined
        };

        // node holds branch A (tip = 2A)
        let n = node_with(st_a, vec![b1.clone(), b2a.clone()], "10.0.0.21:18444");
        assert_eq!(n.best_height(), 2);

        // rival branch: blocks 2B and 3 (LONGER) — mined off the same block 1
        let mut st_b = st0.clone();
        let b2b = {
            let blk = Block {
                height: 2,
                prev_hash: st_b.tip_hash.clone(),
                timestamp: 1_700_000_200,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    2,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st_b.apply_block(&mined, REWARD).expect("apply");
            mined
        };
        let b3 = {
            let blk = Block {
                height: 3,
                prev_hash: st_b.tip_hash.clone(),
                timestamp: 1_700_000_300,
                transactions: vec![crate::chain::coinbase(
                    kp.public_key.bytes.clone(),
                    REWARD,
                    3,
                )],
                nonce: 0,
            };
            let mined = crate::chain::mine_block(blk, D, 2_000_000).expect("mine");
            st_b.apply_block(&mined, REWARD).expect("apply");
            mined
        };

        // 2B arrives first: same height sibling → stashed, tip unchanged
        n.apply_incoming(&b2b).expect("stash sibling");
        assert_eq!(n.best_height(), 2);

        // block 3 arrives: branch (1←2B←3) is fully known & LONGER → reorg
        n.apply_incoming(&b3).expect("reorg");
        assert_eq!(n.best_height(), 3, "reorged to the longer branch");
        assert_eq!(n.chain.lock().unwrap().tip_hash, b3.hash());
        // store now holds exactly the winning branch
        let hashes: Vec<String> = n.blocks.lock().unwrap().iter().map(|b| b.hash()).collect();
        assert!(hashes.contains(&b3.hash()));
        assert!(hashes.contains(&b2b.hash()));
        assert!(
            !hashes.contains(&b2a.hash()),
            "orphaned block removed from store"
        );
    }

    #[test]
    fn bad_push_block_is_rejected() {
        // A pushes a garbage block to B: B must reject it (BadBlock) and its
        // chain must stay untouched.
        let b = node_with(ChainState::new(D), Vec::new(), "10.0.0.5:18444");
        let junk = fake_block(1, ""); // no PoW, wrong chaining
        let err = b.apply_incoming(&junk).unwrap_err();
        assert!(matches!(err, NetError::BadBlock(_)));
        assert_eq!(b.best_height(), 0);
        assert!(b.blocks.lock().unwrap().is_empty());
    }
}
