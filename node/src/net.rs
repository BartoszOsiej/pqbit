//! pqbit-node p2p scaffold (phase 3, start).
//!
//! Honest scope, in order of value:
//!   1. length-prefixed framing (4-byte LE) with a hard 4 MiB cap,
//!   2. magic/version handshake so two nodes can greet each other,
//!   3. Ping/Pong liveness,
//!   4. full-block PULL sync: a peer asks `GetBlocks(from_height)` and gets
//!      every block above that height in one shot.
//!
//! Deliberately NOT here yet (next steps): addr manager, push relay/gossip,
//! reorg handling, rate limiting. This file is the smallest honest skeleton
//! two real nodes can already sync from — boring, auditable, std-only.

// Client-side pull codec lands with the next milestone; today the tests are
// its only caller, so silence dead_code until the CLI gets `sync`/`pull`.
#![allow(dead_code)]

use crate::chain::Block;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Protocol magic: "PQBT".
pub const MAGIC: u32 = 0x5051_4254;
/// Wire protocol version (bump on breaking change).
pub const VERSION: u32 = 1;
/// Hard cap for a single framed message (4 MiB; a full PQ block is far below).
pub const MAX_MSG: usize = 4 * 1024 * 1024;
/// Per-read timeout; a silent peer gets dropped instead of pinned.
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);

pub const MSG_HANDSHAKE: u8 = 0x01;
pub const MSG_PING: u8 = 0x02;
pub const MSG_PONG: u8 = 0x03;
pub const MSG_GETBLOCKS: u8 = 0x04;
pub const MSG_BLOCKS: u8 = 0x05;

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
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io: {e}"),
            NetError::TooLarge => write!(f, "frame exceeds MAX_MSG"),
            NetError::Truncated => write!(f, "payload truncated mid-field"),
            NetError::BadMagic => write!(f, "peer magic mismatch"),
            NetError::UnknownMsg(k) => write!(f, "unknown message type 0x{k:02x}"),
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
// peer loop
// ---------------------------------------------------------------------------

/// Serve one connection: handshake, then answer Ping and GetBlocks until EOF.
pub fn handle_conn(mut stream: TcpStream, blocks: &Arc<Mutex<Vec<Block>>>) -> Result<(), NetError> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let m = read_message(&mut stream)?;
    if m.kind != MSG_HANDSHAKE {
        return Err(NetError::UnknownMsg(m.kind));
    }
    let (magic, _version, _their_height) = decode_handshake(&m.payload)?;
    if magic != MAGIC {
        return Err(NetError::BadMagic);
    }
    let our_height = blocks
        .lock()
        .expect("block store poisoned")
        .last()
        .map(|b| b.height)
        .unwrap_or(0);
    write_message(
        &mut stream,
        MSG_HANDSHAKE,
        &encode_handshake(MAGIC, VERSION, our_height),
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
                let store = blocks.lock().expect("block store poisoned");
                let reply: Vec<Block> = store.iter().filter(|b| b.height > from).cloned().collect();
                drop(store);
                write_message(&mut stream, MSG_BLOCKS, &encode_blocks(&reply))?;
            }
            other => return Err(NetError::UnknownMsg(other)),
        }
    }
}

/// Bind + accept loop (one thread per connection).
pub fn serve(listener: TcpListener, blocks: Arc<Mutex<Vec<Block>>>) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let blocks = Arc::clone(&blocks);
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(s, &blocks) {
                        eprintln!("pqbit-net: peer dropped: {e}");
                    }
                });
            }
            Err(e) => eprintln!("pqbit-net: accept error: {e}"),
        }
    }
    Ok(())
}

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
    use pqbit_core::{Transaction, TxOut};

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
    fn end_to_end_sync_two_nodes() {
        // node A: a real 2-block chain mined with the actual PQ miner
        use crate::chain::{mine_block, coinbase, ChainState};
        use pqbit_core::{generate_pq_keypair, SigAlgo};

        let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
        let reward = 50u64;
        let mut st = ChainState::new(8);
        let mut store: Vec<Block> = Vec::new();
        for h in 1..=2u64 {
            let blk = Block {
                height: st.tip_height + 1,
                prev_hash: st.tip_hash.clone(),
                timestamp: 1_700_000_000 + h,
                transactions: vec![coinbase(kp.public_key.bytes.clone(), reward, st.tip_height + 1)],
                nonce: 0,
            };
            let mined = mine_block(blk, 8, 2_000_000).expect("mine");
            st.apply_block(&mined, reward).expect("apply");
            store.push(mined);
        }
        let tip = st.tip_hash.clone();

        // serve A
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let shared = Arc::new(Mutex::new(store));
        let shared2 = Arc::clone(&shared);
        let server = std::thread::spawn(move || {
            let _ = handle_conn(
                listener.accept().expect("accept").0,
                &shared2,
            );
        });

        // node B: fresh, pulls everything, applies, reaches the same tip
        let (their_height, blocks) = pull_blocks(&addr, 0).expect("pull");
        assert_eq!(their_height, 2);
        assert_eq!(blocks.len(), 2);
        let mut st_b = ChainState::new(8);
        for b in &blocks {
            st_b.apply_block(b, reward).expect("B applies valid block");
        }
        assert_eq!(st_b.tip_hash, tip, "B must land on A's tip");
        assert_eq!(st_b.total_supply, 100); // 2 × 50

        server.join().expect("server thread");
    }
}
