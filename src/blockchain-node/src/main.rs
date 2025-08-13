use std::{collections::HashMap, env, fs, io, net::SocketAddr, path::{Path, PathBuf}, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use axum::{routing::{get, post}, Json, Router, extract::State};
use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

static GENESIS_PREV_HASH: Lazy<String> = Lazy::new(|| "0".repeat(64));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")] 
pub enum TxType {
    Mint,
    Transfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type: TxType,
    pub from: Option<String>,
    pub to: String,
    pub amount: u64,
    pub signature: Option<String>, // placeholder for MVP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub prev_hash: String,
    pub timestamp: u64,
    pub nonce: u64, // not used for PoA, kept for extensibility
    pub proposer: String, // PoA authority ID
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub hash: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub balances: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    chain: Vec<Block>,
    state: ChainState,
}

#[derive(Debug, Default)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub state: ChainState,
    pub authorities: Vec<String>,
    data_dir: PathBuf,
}

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("unauthorized proposer")] 
    Unauthorized,
    #[error("insufficient balance")] 
    InsufficientBalance,
    #[error("invalid transaction")] 
    InvalidTx,
    #[error("storage error: {0}")]
    Storage(String),
}

impl Blockchain {
    pub fn new(authorities: Vec<String>, data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        if let Err(e) = fs::create_dir_all(&data_dir) {
            tracing::warn!(error = %e, "failed to create data dir, proceeding");
        }
        match Self::load_snapshot(&data_dir) {
            Ok(Some(snapshot)) => {
                Self { chain: snapshot.chain, state: snapshot.state, authorities, data_dir }
            }
            Ok(None) | Err(_) => {
                let mut bc = Self { chain: vec![], state: ChainState::default(), authorities, data_dir };
                bc.init_genesis();
                // Best-effort save genesis
                let _ = bc.save_snapshot(&bc.chain, &bc.state);
                bc
            }
        }
    }

    fn init_genesis(&mut self) {
        let header = BlockHeader {
            prev_hash: GENESIS_PREV_HASH.clone(),
            timestamp: now_ts(),
            nonce: 0,
            proposer: "genesis".to_string(),
        };
        let transactions = vec![];
        let hash = block_hash(&header, &transactions);
        let block = Block { header, transactions, hash };
        self.chain.push(block);
    }

    fn apply_tx(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        match tx.tx_type {
            TxType::Mint => {
                // Only authority can mint; validated before adding block in this MVP
                let to_bal = self.state.balances.entry(tx.to.clone()).or_default();
                *to_bal = to_bal.saturating_add(tx.amount);
                Ok(())
            }
            TxType::Transfer => {
                let from = tx.from.clone().ok_or(ChainError::InvalidTx)?;
                let from_bal = self.state.balances.entry(from.clone()).or_default();
                if *from_bal < tx.amount { return Err(ChainError::InsufficientBalance); }
                *from_bal -= tx.amount;
                let to_bal = self.state.balances.entry(tx.to.clone()).or_default();
                *to_bal = to_bal.saturating_add(tx.amount);
                Ok(())
            }
        }
    }

    pub fn add_block(&mut self, proposer: &str, txs: Vec<Transaction>) -> Result<&Block, ChainError> {
        if !self.authorities.iter().any(|a| a == proposer) && proposer != "genesis" {
            return Err(ChainError::Unauthorized);
        }
        // Clone state for atomicity; on error, state not changed
        let mut new_state = self.state.clone();
        for tx in &txs {
            // Validate mint authorization: for MVP, require tx.from to equal proposer for Mint
            if matches!(tx.tx_type, TxType::Mint) {
                if tx.from.as_deref() != Some(proposer) {
                    return Err(ChainError::Unauthorized);
                }
            }
            // Apply into temp state
            match apply_tx_into(&mut new_state, tx) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
        }
        let prev_hash = self.chain.last().map(|b| b.hash.clone()).unwrap_or_else(|| GENESIS_PREV_HASH.clone());
        let header = BlockHeader { prev_hash, timestamp: now_ts(), nonce: 0, proposer: proposer.to_string() };
        let hash = block_hash(&header, &txs);
        let block = Block { header, transactions: txs, hash };
        // prepare new chain
        let mut new_chain = self.chain.clone();
        new_chain.push(block);
        // persist snapshot first
        self.save_snapshot(&new_chain, &new_state)
            .map_err(|e| ChainError::Storage(e.to_string()))?;
        // commit in-memory after successful persist
        self.state = new_state;
        self.chain = new_chain;
        Ok(self.chain.last().unwrap())
    }

    fn snapshot_path(dir: &Path) -> PathBuf { dir.join("snapshot.json") }

    fn load_snapshot(dir: &Path) -> io::Result<Option<Snapshot>> {
        let path = Self::snapshot_path(dir);
        if !path.exists() { return Ok(None); }
        let data = fs::read(&path)?;
        let snap: Snapshot = serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(snap))
    }

    fn save_snapshot(&self, chain: &Vec<Block>, state: &ChainState) -> io::Result<()> {
        let snap = Snapshot { chain: chain.clone(), state: state.clone() };
        let bytes = serde_json::to_vec_pretty(&snap)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let final_path = Self::snapshot_path(&self.data_dir);
        let tmp_path = final_path.with_extension("json.tmp");
        fs::write(&tmp_path, &bytes)?;
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }
}

fn apply_tx_into(state: &mut ChainState, tx: &Transaction) -> Result<(), ChainError> {
    match tx.tx_type {
        TxType::Mint => {
            let to_bal = state.balances.entry(tx.to.clone()).or_default();
            *to_bal = to_bal.saturating_add(tx.amount);
            Ok(())
        }
        TxType::Transfer => {
            let from = tx.from.clone().ok_or(ChainError::InvalidTx)?;
            let from_bal = state.balances.entry(from.clone()).or_default();
            if *from_bal < tx.amount { return Err(ChainError::InsufficientBalance); }
            *from_bal -= tx.amount;
            let to_bal = state.balances.entry(tx.to.clone()).or_default();
            *to_bal = to_bal.saturating_add(tx.amount);
            Ok(())
        }
    }
}

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn block_hash(header: &BlockHeader, txs: &Vec<Transaction>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&header.prev_hash);
    hasher.update(header.timestamp.to_le_bytes());
    hasher.update(header.nonce.to_le_bytes());
    hasher.update(&header.proposer);
    let body = serde_json::to_vec(txs).unwrap();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

#[derive(Clone, Default)]
struct AppState {
    chain: Arc<RwLock<Blockchain>>,
    mint_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MintRequest { proposer: String, to: String, amount: u64 }

#[derive(Debug, Deserialize)]
struct TransferRequest { proposer: String, from: String, to: String, amount: u64 }

#[tokio::main]
async fn main() {
    init_tracing();
    let authorities = load_authorities();
    let data_dir = env::var("DEVCOIN_DATA_DIR").unwrap_or_else(|_| "src/blockchain-node/data".to_string());
    let mint_token = env::var("DEVCOIN_MINT_TOKEN").ok();
    let state = AppState { chain: Arc::new(RwLock::new(Blockchain::new(authorities, data_dir))), mint_token };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
    .route("/mint", post(mint))
        .route("/transfer", post(transfer))
        .route("/balance/:user", get(balance))
        .route("/chain", get(get_chain))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_max_level(Level::INFO)
        .init();
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("Authorization") {
        if let Ok(s) = v.to_str() {
            let prefix = "Bearer ";
            if let Some(rest) = s.strip_prefix(prefix) { return Some(rest.trim().to_string()); }
        }
    }
    if let Some(v) = headers.get("X-Devcoin-Token") {
        if let Ok(s) = v.to_str() { return Some(s.trim().to_string()); }
    }
    None
}

async fn mint(State(state): State<AppState>, headers: HeaderMap, Json(req): Json<MintRequest>) -> Json<serde_json::Value> {
    // If a mint token is configured, require it
    if let Some(expected) = &state.mint_token {
        let got = extract_bearer_token(&headers);
        if got.as_deref() != Some(expected.as_str()) {
            return Json(json!({"status":"error","message":"unauthorized"}));
        }
    }
    let tx = Transaction { tx_type: TxType::Mint, from: Some(req.proposer.clone()), to: req.to, amount: req.amount, signature: None };
    let mut chain = state.chain.write().await;
    let res = chain.add_block(&req.proposer, vec![tx]);
    match res {
        Ok(block) => Json(json!({"status":"ok","block_hash": block.hash})),
        Err(e) => Json(json!({"status":"error","message": e.to_string()})),
    }
}

async fn transfer(State(state): State<AppState>, Json(req): Json<TransferRequest>) -> Json<serde_json::Value> {
    let tx = Transaction { tx_type: TxType::Transfer, from: Some(req.from), to: req.to, amount: req.amount, signature: None };
    let mut chain = state.chain.write().await;
    let res = chain.add_block(&req.proposer, vec![tx]);
    match res {
        Ok(block) => Json(json!({"status":"ok","block_hash": block.hash})),
        Err(e) => Json(json!({"status":"error","message": e.to_string()})),
    }
}

async fn balance(State(state): State<AppState>, axum::extract::Path(user): axum::extract::Path<String>) -> Json<serde_json::Value> {
    let chain = state.chain.read().await;
    let bal = chain.state.balances.get(&user).cloned().unwrap_or(0);
    Json(json!({"user": user, "balance": bal}))
}

async fn get_chain(State(state): State<AppState>) -> Json<Vec<Block>> {
    let chain = state.chain.read().await;
    Json(chain.chain.clone())
}

fn load_authorities() -> Vec<String> {
    match env::var("DEVCOIN_AUTHORITIES") {
        Ok(val) => val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => vec!["authority1".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    #[test]
    fn test_mint_and_transfer() {
        let authorities = vec!["authority1".to_string()];
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("devcoin_test_{}", now_ts()));
        let mut chain = Blockchain::new(authorities, tmp);

        // Mint 100 to alice by authority1
        let mint_tx = Transaction { tx_type: TxType::Mint, from: Some("authority1".into()), to: "alice".into(), amount: 100, signature: None };
        chain.add_block("authority1", vec![mint_tx]).expect("mint ok");
        assert_eq!(*chain.state.balances.get("alice").unwrap_or(&0), 100);

        // Transfer 40 from alice to bob
        let transfer_tx = Transaction { tx_type: TxType::Transfer, from: Some("alice".into()), to: "bob".into(), amount: 40, signature: None };
        chain.add_block("authority1", vec![transfer_tx]).expect("transfer ok");
        assert_eq!(*chain.state.balances.get("alice").unwrap_or(&0), 60);
        assert_eq!(*chain.state.balances.get("bob").unwrap_or(&0), 40);
    }
}
