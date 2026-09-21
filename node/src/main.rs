//! pqbit-node — lightweight post-quantum Bitcoin testnet node (Hartwell Labs).
//!
//! Phase-3 CLI adds `serve`: a p2p peer that shares its chain for pull-sync.
//!
//! Phase-2 CLI: mine a toy chain, validate it. Phase 3 in progress: p2p
//! (framing + handshake + pull sync in net.rs); gossip/addr manager next.
//! Everything here is honest, local and PQ-verified.

mod chain;
mod net;

use chain::{mine_block, Block, ChainState};
use clap::{Parser, Subcommand};
use pqbit_core::{generate_pq_keypair, SigAlgo};

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
    },
    /// Verify the PQ signing machinery end-to-end (keygen → sign → verify)
    SelfTest,
    /// Mine a local chain and serve it for pull-sync: `pqbit-node serve`
    Serve {
        #[arg(long, default_value_t = 5)]
        blocks: u64,
        #[arg(long, default_value_t = 12)]
        difficulty: u32,
        #[arg(long, default_value_t = 50)]
        reward: u64,
        #[arg(long, default_value = "127.0.0.1:18444")]
        listen: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Mine { blocks, difficulty, reward } => {
            println!("pqbit-node :: testnet miner");
            println!("  difficulty : {difficulty} leading zero bits");
            println!("  reward     : {reward} pq-sats / block");
            println!();
            let mut st = ChainState::new(difficulty);
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            let t0 = std::time::Instant::now();
            for i in 1..=blocks {
                let blk = Block {
                    height: st.tip_height + 1,
                    prev_hash: st.tip_hash.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    transactions: vec![chain::coinbase(kp.public_key.bytes.clone(), reward, st.tip_height + 1)],
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
        }
        Cmd::SelfTest => {
            let kp = generate_pq_keypair(SigAlgo::MlDsa44).expect("keygen");
            let msg = b"pqbit selftest";
            let sig = pqbit_core::sign_pq(SigAlgo::MlDsa44, &kp.secret_key.bytes, msg).expect("sign");
            let ok = pqbit_core::verify_pq(SigAlgo::MlDsa44, &kp.public_key.bytes, msg, &sig).expect("verify");
            println!("ML-DSA-44 keygen/sign/verify: {}", if ok { "PASS" } else { "FAIL" });
            std::process::exit(if ok { 0 } else { 1 });
        }
        Cmd::Serve { blocks, difficulty, reward, listen } => {
            println!("pqbit-node :: p2p peer (phase 3 scaffold — pull sync)");
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
            println!("  peers can : handshake, ping, GetBlocks → full blocks");
            let listener = std::net::TcpListener::bind(&listen).expect("bind");
            net::serve(listener, store).expect("serve loop");
        }
    }
}
