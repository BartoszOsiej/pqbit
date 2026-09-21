//! pqbit-node — lightweight post-quantum Bitcoin testnet node (Hartwell Labs).
//!
//! Phase-3 CLI adds `serve`: a gossiping p2p peer. It mines its chain, then
//! exchanges addr books and blocks with peers it dials (seeds) — pull when
//! they are taller, push when we are, every block PQ-validated on arrival.

mod chain;
mod mempool;
mod net;

use chain::{mine_block, Block, ChainState};
use clap::{Parser, Subcommand};
use pqbit_core::{generate_pq_keypair, SigAlgo};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "pqbit-node", about = "Post-quantum Bitcoin testnet node (Hartwell Labs)", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mine a fresh local chain: `pqbit-node mine --blocks 3`
    Mine {
        #[arg(long, default_value_t = 3)]
        blocks: u64,
        #[arg(long, default_value_t = 12)]
        difficulty: u32,
        #[arg(long, default_value_t = 50)]
        reward: u64,
        /// Payout address (pubkey hex); defaults to a fresh keypair
        #[arg(long)]
        payout: Option<String>,
        /// Dump the UTXO set after mining ("value pubkey_hex" lines)
        #[arg(long)]
        dump_utxos: Option<String>,
        /// Extended dump format: "value pubkey_hex txid_hex vout" (for `send`)
        #[arg(long, default_value_t = false)]
        extended: bool,
    },
    /// Verify the PQ signing machinery end-to-end (keygen → sign → verify)
    SelfTest,
    /// Validate a signed tx (wire hex from `send`) against a UTXO dump;
    /// exit 0 = would enter mempool. Future RPC injection point.
    Submit {
        /// Path to file with the tx wire-hex (from `send --out`)
        #[arg(long)]
        tx: String,
        /// Extended UTXO dump (from `mine/serve --dump-utxos --extended`)
        #[arg(long)]
        utxos: String,
    },
    /// Generate a new PQ keypair (a wallet): prints the public key (used as
    /// the payout address in coinbase/outputs) and the secret key.
    ///
    /// Storage is intentionally dumb v1: hex files the user keeps safe.
    /// A real wallet (encryption, change addresses) comes with phase 4.
    Wallet {
        /// Write keys to files instead of stdout (pqbit.pk / pqbit.sk)
        #[arg(long, default_value_t = false)]
        write: bool,
    },
    /// Show balance for a payout address (public key hex) by scanning an
    /// UTXO-export file (plain text, one `value pubkey_hex` per line; written
    /// by `serve --dump-utxos` at shutdown — no serde, per repo rules).
    Balance {
        /// Public key hex (the payout address)
        #[arg(long)]
        address: String,
        /// UTXO export file ("value pubkey_hex" lines)
        #[arg(long)]
        utxos: String,
    },
    /// Build a signed spend from YOUR secret key (pqbit.sk) to a recipient
    /// address, writing the wire-encoded transaction to a file. v1 spends
    /// the FIRST UTXO found in `--owned` (an export listing your UTXOs with
    /// txid/vout: "value pubkey_hex txid_hex vout" — extended dump from
    /// `serve --dump-utxos --extended`).
    Send {
        #[arg(long, default_value = "pqbit.sk")]
        sk: String,
        /// Public key file (wallet --write creates it); UTXOs are matched by pubkey
        #[arg(long, default_value = "pqbit.pk")]
        pk: String,
        #[arg(long)]
        owned: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        out: String,
    },
    /// Mine a local chain and gossip with peers: `pqbit-node serve --seed 127.0.0.1:18445`
    Serve {
        #[arg(long, default_value_t = 5)]
        blocks: u64,
        #[arg(long, default_value_t = 12)]
        difficulty: u32,
        #[arg(long, default_value_t = 50)]
        reward: u64,
        #[arg(long, default_value = "127.0.0.1:18444")]
        listen: String,
        /// Peer address to gossip with (repeatable)
        #[arg(long = "seed")]
        seeds: Vec<String>,
        /// Gossip interval in seconds
        #[arg(long, default_value_t = 10)]
        interval: u64,
        /// Keep mining new blocks on the tip forever (packs mempool txs)
        #[arg(long, default_value_t = false)]
        keep_mining: bool,
        /// Dump the UTXO set ("value pubkey_hex" lines) to this file after mining
        #[arg(long)]
        dump_utxos: Option<String>,
        /// Extended dump: "value pubkey_hex txid_hex vout" (for `send`)
        #[arg(long, default_value_t = false)]
        extended: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Mine { blocks, difficulty, reward, payout, dump_utxos, extended } => {
            println!("pqbit-node :: testnet miner");
            println!("  difficulty : {difficulty} leading zero bits");
            println!("  reward     : {reward} pq-sats / block");
            println!();
            let mut st = ChainState::new(difficulty);
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            let payout_pk: Vec<u8> = match &payout {
                Some(h) => hex::decode(h).expect("payout hex"),
                None => kp.public_key.bytes.clone(),
            };
            let t0 = std::time::Instant::now();
            for i in 1..=blocks {
                let blk = Block {
                    height: st.tip_height + 1,
                    prev_hash: st.tip_hash.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    transactions: vec![chain::coinbase(payout_pk.clone(), reward, st.tip_height + 1)],
                    nonce: 0,
                };
                let mined = mine_block(blk, difficulty, 200_000_000).expect("mining budget");
                let h = mined.hash();
                let took = t0.elapsed().as_secs_f64();
                st.apply_block(&mined, reward).expect("valid block");
                println!(
                    "  block {i:>3}  hash={}…  nonce={:>10}  supply={}  ({:.1}s total)",
                    &h[..16],
                    mined.nonce,
                    st.total_supply,
                    took
                );
            }
            println!();
            println!("  chain tip  : {}", &st.tip_hash[..32]);
            println!("  utxos      : {}", st.utxos.len());
            println!("  status     : OK — PoW + PQ coinbase committed");
            if let Some(path) = &dump_utxos {
                use std::io::Write;
                let mut f = std::fs::File::create(path).expect("create utxo dump");
                for ((txid, vout), (v, pk)) in st.utxos.iter() {
                    if extended {
                        let _ = writeln!(f, "{v} {} {txid} {vout}", hex::encode(pk));
                    } else {
                        let _ = writeln!(f, "{v} {}", hex::encode(pk));
                    }
                }
                println!("  utxo dump : {path}");
            }
        }
        Cmd::Wallet { write } => {
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            if write {
                use std::io::Write;
                let mut pk = std::fs::File::create("pqbit.pk").expect("create pk");
                pk.write_all(hex::encode(&kp.public_key.bytes).as_bytes())
                    .expect("write pk");
                let mut sk = std::fs::File::create("pqbit.sk").expect("create sk");
                sk.write_all(hex::encode(&kp.secret_key.bytes).as_bytes())
                    .expect("write sk");
                println!("wrote pqbit.pk (public / payout address) and pqbit.sk (SECRET — keep offline)");
                println!("chmod 600 pqbit.sk recommended");
            } else {
                println!("pqbit wallet (ML-DSA-44 / FIPS 204)");
                println!();
                println!("  public key (payout address):");
                println!("    {}", hex::encode(&kp.public_key.bytes));
                println!();
                println!("  secret key (NEVER share; this is the only copy):", );
                println!("    {}", hex::encode(&kp.secret_key.bytes));
                println!();
                println!("usage: the public key hex is what others pay to; the secret
key signs spends. Re-run with --write to store as files.");
            }
        }
        Cmd::Balance { address, utxos } => {
            let raw = std::fs::read_to_string(&utxos).expect("read utxos file");
            let mut st = ChainState::new(0);
            for line in raw.lines() {
                let it: Vec<&str> = line.split_whitespace().collect();
                match it.len() {
                    // simple dump: "value pubkey"
                    2 => {
                        let v: u64 = it[0].parse().unwrap_or(0);
                        if let Ok(pk) = hex::decode(it[1]) {
                            // synthetic key: empty txid is fine for balance lookups
                            st.utxos.insert((String::new(), st.utxos.len() as u32), (v, pk));
                        }
                    }
                    // extended dump: "value pubkey txid vout"
                    4 => {
                        let v: u64 = it[0].parse().unwrap_or(0);
                        if let Ok(pk) = hex::decode(it[1]) {
                            st.utxos.insert((it[2].to_string(), it[3].parse().unwrap_or(0)), (v, pk));
                        }
                    }
                    _ => {}
                }
            }
            let pk_bytes = hex::decode(&address).unwrap_or_default();
            let total = st.balance_of(&pk_bytes);
            let count = st.utxos_of(&pk_bytes).len();
            println!("address   : {}…", &address[..16.min(address.len())]);
            println!("utxos     : {count}");
            println!("balance   : {total} pq-sats");
        }
        Cmd::Send { sk, pk, owned, to, out } => {
            use pqbit_core::{sign_pq, verify_pq, SigAlgo, TxIn, TxOut, Transaction};
            use std::io::Write;

            let sk_hex = std::fs::read_to_string(&sk).expect("read sk").trim().to_string();
            let sk_bytes = hex::decode(&sk_hex).expect("sk hex");
            let pk_hex = std::fs::read_to_string(&pk).expect("read pk (run `wallet --write` first)").trim().to_string();
            let to_bytes = hex::decode(&to).expect("to hex");

            // first UTXO owned by our pk: extended dump format "value pubkey txid vout"
            let raw = std::fs::read_to_string(&owned).expect("read owned");
            let mut found: Option<(u64, String, u32)> = None;
            for line in raw.lines() {
                let it: Vec<&str> = line.split_whitespace().collect();
                if it.len() == 4 && it[1] == pk_hex {
                    found = Some((it[0].parse().expect("value"), it[2].to_string(), it[3].parse().expect("vout")));
                    break;
                }
            }
            let (value, txid_hex, vout) = found.expect("no owned UTXO in file (need --extended dump)");

            let mut tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prev_txid: hex::decode(&txid_hex).expect("txid").try_into().expect("32 bytes"),
                    vout,
                    signature: vec![],
                }],
                outputs: vec![TxOut {
                    value,
                    pubkey: to_bytes,
                }],
                locktime: 0,
            };
            tx.inputs[0].signature =
                sign_pq(SigAlgo::MlDsa44, &sk_bytes, &tx.sighash()).expect("sign");

            // self-check before writing: the spend must verify against our own pk
            let pk_bytes = hex::decode(&pk_hex).expect("pk hex");
            let ok = verify_pq(SigAlgo::MlDsa44, &pk_bytes, &tx.sighash(), &tx.inputs[0].signature)
                .unwrap_or(false);
            if !ok {
                eprintln!("ERROR: signed tx failed self-verification against {pk} — aborting");
                std::process::exit(1);
            }

            let wire = crate::mempool::encode_tx(&tx);
            let mut f = std::fs::File::create(&out).expect("create out");
            f.write_all(hex::encode(&wire).as_bytes()).expect("write");
            println!("signed spend:");
            println!("  spends  : txid {}… vout {vout} ({} pq-sats)", &txid_hex[..16.min(txid_hex.len())], value);
            println!("  to      : {}…", &to[..16.min(to.len())]);
            println!("  tx file : {out} (wire hex — inject via a future `submit` RPC)");
        }
        Cmd::Submit { tx, utxos } => {
            use crate::mempool::Mempool;

            let hex_str = std::fs::read_to_string(&tx).expect("read tx file").trim().to_string();
            let wire = hex::decode(&hex_str).expect("tx hex");
            let decoded = mempool::decode_tx(&wire).expect("decode tx");
            let transaction = &decoded;

            // rebuild a ChainState from the extended UTXO dump
            let mut st = ChainState::new(0);
            let raw = std::fs::read_to_string(&utxos).expect("read utxos");
            for line in raw.lines() {
                let it: Vec<&str> = line.split_whitespace().collect();
                if it.len() == 4 {
                    let v: u64 = it[0].parse().expect("value");
                    let pk = hex::decode(it[1]).expect("pk hex");
                    let txid = it[2].to_string();
                    let vout: u32 = it[3].parse().expect("vout");
                    st.utxos.insert((txid, vout), (v, pk));
                }
            }

            let mut pool = Mempool::new();
            match pool.accept(transaction, &st) {
                Ok(()) => {
                    let txid = hex::encode(transaction.sighash());
                    println!("tx {}… ACCEPTED ({} input(s), {} output(s)) — valid against UTXO dump", &txid[..16], transaction.inputs.len(), transaction.outputs.len());
                }
                Err(e) => {
                    eprintln!("REJECTED: {e:?}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::SelfTest => {
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            let msg = b"pqbit selftest";
            let sig = pqbit_core::sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, msg).expect("sign");
            let ok = pqbit_core::verify_pq(SigAlgo::MlDsa44, &kp.public_key.bytes, msg, &sig).expect("verify");
            println!("ML-DSA-44 keygen/sign/verify: {}", if ok { "PASS" } else { "FAIL" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        Cmd::Serve { blocks, difficulty, reward, listen, seeds, interval, keep_mining, dump_utxos, extended } => {
            println!("pqbit-node :: p2p peer (phase 3 — gossip: addr exchange + push/pull)");
            println!("  mining {} blocks @ {} bits, serving on {}", blocks, difficulty, listen);
            println!();
            let mut st = ChainState::new(difficulty);
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            let store: std::sync::Arc<std::sync::Mutex<Vec<chain::Block>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            for i in 1..=blocks {
                let blk = chain::Block {
                    height: st.tip_height + 1,
                    prev_hash: st.tip_hash.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    transactions: vec![chain::coinbase(kp.public_key.bytes.clone(), reward, st.tip_height + 1)],
                    nonce: 0,
                };
                let mined = chain::mine_block(blk, difficulty, 200_000_000).expect("mining budget");
                st.apply_block(&mined, reward).expect("valid block");
                store.lock().expect("store").push(mined);
                println!("  block {i:>3}  tip={}…  supply={}", &st.tip_hash[..16], st.total_supply);
            }
            println!();
            println!("  serving   : {listen}  (magic={:#010x}, wire v{})", net::MAGIC, net::VERSION);
            if !seeds.is_empty() {
                println!("  gossiping : {} @ {}s interval", seeds.join(", "), interval);
            }
            println!("  peers can : handshake, ping, GetBlocks, GetAddr, push blocks");

            let state = net::NodeState {
                listen: listen.clone(),
                reward,
                blocks: Arc::clone(&store),
                chain: std::sync::Arc::new(std::sync::Mutex::new(st)),
                book: std::sync::Arc::new(std::sync::Mutex::new(net::AddrBook::new())),
                pool: std::sync::Arc::new(std::sync::Mutex::new(mempool::Mempool::new())),
                miner_key: Arc::new(kp.public_key.bytes.clone()),
            };
            if let Some(path) = &dump_utxos {
                use std::io::Write;
                let mut f = std::fs::File::create(path).expect("create utxo dump");
                let chain_now = state.chain.lock().expect("chain poisoned");
                for ((txid, vout), (v, pk)) in chain_now.utxos.iter() {
                    if extended {
                        let _ = writeln!(f, "{v} {} {txid} {vout}", hex::encode(pk));
                    } else {
                        let _ = writeln!(f, "{v} {}", hex::encode(pk));
                    }
                }
                drop(chain_now);
                println!("  utxo dump : {path}");
            }
            if keep_mining {
                println!("  mining    : continuous (packs mempool txs, reward to our key)");
                let m = state.clone();
                std::thread::spawn(move || loop {
                    match net::mine_one(&m, difficulty, 200_000_000) {
                        Ok(b) => {
                            eprintln!(
                                "pqbit-mine: block {}  txs={}  tip={}…",
                                b.height,
                                b.transactions.len() - 1,
                                &b.hash()[..16]
                            );
                        }
                        Err(e) => eprintln!("pqbit-mine: {e}"),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                });
            }
            // background gossiper (seeds + learned addrs) while we accept peers
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            if !seeds.is_empty() {
                let g = state.clone();
                let s2 = seeds.clone();
                let stop2 = Arc::clone(&stop);
                std::thread::spawn(move || {
                    net::gossiper_loop(s2, g, std::time::Duration::from_secs(interval), stop2);
                });
            }
            let listener = std::net::TcpListener::bind(&listen).expect("bind");
            let _ = net::serve(listener, state); // runs until process ends
            let _ = stop;
        }
    }
}
