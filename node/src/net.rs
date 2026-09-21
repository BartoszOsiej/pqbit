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
//!   7. a background gossiper loop running connect-sync-disconnect rounds.
//!
//! Deliberately NOT here yet: persistent connections, unsolicited re-relay
//! (periodic rounds propagate instead — bounded traffic), NAT traversal,
//! reorg handling, rate limiting. Boring, auditable, std-only.

#![allow(dead_code)]

use crate::chain::{ChainState, NodeError, Block};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Protocol magic: "PQBT".
pub const MAGIC: u32 = 0x5051_4254;
/// Wire protocol version (bump on breaking change).
pub const VERSION: u32 = 2;
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
#[derive(Default)]
pub struct AddrBook {
    map: HashMap<String, u64>,
}

impl AddrBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge one addr. Returns true if it was new. Rejects junk and, when the
    /// book is full, unknown addrs (known ones just get their last-seen bumped).
    pub fn merge(&mut self, addr: &str, now: u64) -> bool {
        let ok = !addr.is_empty()
            && addr.len() <= 64
            && !addr.contains(char::is_whitespace)
            && addr.contains(':');
        if !ok {
            return false;
        }
        if let Some(seen) = self.map.get_mut(addr) {
            *seen = now;
            return false;
        }
        if self.map.len() >= MAX_BOOK {
            return false;
        }
        self.map.insert(addr.to_string(), now);
        true
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
}

impl NodeState {
    pub fn best_height(&self) -> u64 {
        self.chain
            .lock()
            .expect("chain poisoned")
            .tip_height
    }

    /// Validate + apply one incoming block. Duplicates (height ≤ tip) are a
    /// silent no-op; anything our chain rejects surfaces as NetError::BadBlock.
    fn apply_incoming(&self, b: &Block) -> Result<(), NetError> {
        {
            let mut chain = self.chain.lock().expect("chain poisoned");
            if b.height <= chain.tip_height {
                return Ok(());
            }
            chain
                .apply_block(b, self.reward)
                .map_err(NetError::BadBlock)?;
        }
        self.blocks
            .lock()
            .expect("store poisoned")
            .push(b.clone());
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
                return Ok(()) // silent peer: close politely
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
            }
            MSG_BLOCKS => {
                // Unsolicited push from a taller peer. Validate every block;
                // one bad block and we drop the connection (misbehaving peer).
                let blocks = decode_blocks(&m.payload)?;
                for b in &blocks {
                    state.apply_incoming(b)?;
                }
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
}

/// One connect-sync-disconnect round against `peer`:
/// handshake → self-announce → GETADDR → pull or push, depending on heights.
pub fn gossip_round(peer: &str, state: &NodeState) -> Result<GossipRound, NetError> {
    let mut s = TcpStream::connect(peer)?;
    s.set_read_timeout(Some(READ_TIMEOUT))?;

    let our_height = state.best_height();
    write_message(&mut s, MSG_HANDSHAKE, &encode_handshake(MAGIC, VERSION, our_height))?;
    let m = read_message(&mut s)?;
    if m.kind != MSG_HANDSHAKE {
        return Err(NetError::UnknownMsg(m.kind));
    }
    let (magic, _v, their_height) = decode_handshake(&m.payload)?;
    if magic != MAGIC {
        return Err(NetError::BadMagic);
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
    let mut learned = 0usize;
    {
        let mut book = state.book.lock().expect("book poisoned");
        let now = now_unix();
        for a in decode_addrs(&m.payload)? {
            if a == state.listen {
                continue;
            }
            if book.merge(&a, now) {
                learned += 1;
            }
        }
    }

    let mut round = GossipRound {
        their_height,
        learned,
        ..Default::default()
    };

    // 3. sync: pull if they are taller, push if we are
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
    Ok(round)
}

/// Background gossip loop: periodic rounds to every known peer (seeds first,
/// then anything learned along the way). Runs until `stop` is set.
pub fn gossiper_loop(seeds: Vec<String>, state: NodeState, interval: Duration, stop: Arc<AtomicBool>) {
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
                    if r.pulled > 0 || r.pushed > 0 || r.learned > 0 {
                        eprintln!(
                            "pqbit-net: gossip {peer}: +{} pulled, {} pushed, {} addrs learned (their tip {})",
                            r.pulled, r.pushed, r.learned, r.their_height
                        );
                    }
                }
                Err(e) => eprintln!("pqbit-net: gossip {peer} failed: {e}"),
            }
        }
        std::thread::sleep(interval);
    }
}

// ---------------------------------------------------------------------------
// one-shot pull (kept as a primitive for a future `sync` subcommand)
// ---------------------------------------------------------------------------

/// One-shot client: connect, handshake, pull blocks above `from_height`.
/// Returns (their best height, blocks).
pub fn pull_blocks(addr: &str, from_height: u64) -> Result<(u64, Vec<Block>), NetError> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(READ_TIMEOUT))?;
    write_message(&mut s, MSG_HANDSHAKE, &encode_handshake(MAGIC, VERSION, from_height))?;
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
        assert!(b.book.lock().unwrap().addrs().contains(&"10.0.0.9:18444".to_string()));
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
        assert!(b.book.lock().unwrap().addrs().contains(&"10.0.0.3:18444".to_string()));
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
