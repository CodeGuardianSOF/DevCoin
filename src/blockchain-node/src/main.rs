use std::{collections::{HashMap, HashSet}, env, fs, io, net::SocketAddr, path::{Path, PathBuf}, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

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
use ed25519_dalek::{PublicKey as Ed25519PublicKey, Signature as Ed25519Signature, Verifier};
use base64::Engine as _;

fn b64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> { base64::engine::general_purpose::STANDARD.decode(input) }

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
    pub authorities: HashSet<String>,
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
    pub fn new(authorities: HashSet<String>, data_dir: impl Into<PathBuf>) -> Self {
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
        if !self.authorities.contains(proposer) && proposer != "genesis" {
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
    authority_keys: HashMap<String, Ed25519PublicKey>,
    require_sigs: bool,
    seen_nonces: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Deserialize)]
struct MintRequest { proposer: String, to: String, amount: u64, signature: Option<String>, nonce: Option<u64> }

#[derive(Debug, Deserialize)]
struct TransferRequest { proposer: String, from: String, to: String, amount: u64, signature: Option<String>, nonce: Option<u64> }

#[tokio::main]
async fn main() {
    init_tracing();
    let authorities = load_authorities();
    let data_dir = env::var("DEVCOIN_DATA_DIR").unwrap_or_else(|_| "src/blockchain-node/data".to_string());
    let mint_token = env::var("DEVCOIN_MINT_TOKEN").ok();
    let (authority_keys, require_sigs) = load_authority_keys();
    // Startup diagnostics
    info!(
        authorities = ?authorities,
        keys_loaded = authority_keys.len(),
        key_ids = ?authority_keys.keys().cloned().collect::<Vec<_>>(),
        require_sigs = require_sigs,
        "DevCoin node configuration loaded"
    );
    let state = AppState {
        chain: Arc::new(RwLock::new(Blockchain::new(authorities, data_dir))),
        mint_token,
        authority_keys,
        require_sigs,
        seen_nonces: Arc::new(RwLock::new(HashSet::new())),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
    .route("/mint", post(mint))
        .route("/transfer", post(transfer))
        .route("/balance/:user", get(balance))
        .route("/chain", get(get_chain))
        .with_state(state);

    let addr_str = env::var("DEVCOIN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = addr_str.parse().expect("invalid DEVCOIN_ADDR");
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
    // Optional signature verification
    let key_opt = state.authority_keys.get(&req.proposer);
    // Request diagnostics (info level, minimal data)
    info!(
        proposer = %req.proposer,
        have_key = key_opt.is_some(),
        require_sigs = state.require_sigs,
        have_sig = req.signature.as_ref().map(|_| true).unwrap_or(false),
        nonce = req.nonce.unwrap_or(0),
        "mint request received"
    );
    let sig_opt = req.signature.as_ref();
    if state.require_sigs {
        let Some(key) = key_opt else { return Json(json!({"status":"error","message":"unknown authority"})); };
        let Some(sig_b64) = sig_opt else { return Json(json!({"status":"error","message":"missing signature"})); };
        let nonce = req.nonce.unwrap_or(0);
        let msg = format!("mint|{}|{}|{}|{}", req.proposer, req.to, req.amount, nonce);
        match b64_decode(sig_b64)
            .ok()
            .and_then(|b| Ed25519Signature::from_bytes(&b).ok())
            .and_then(|sig| key.verify(msg.as_bytes(), &sig).ok()) {
            Some(()) => {
                let dedup_key = format!("{}:{}", req.proposer, nonce);
                let mut seen = state.seen_nonces.write().await;
                if nonce != 0 {
                    if seen.contains(&dedup_key) { return Json(json!({"status":"error","message":"replay"})); }
                    if seen.len() > 10_000 { seen.clear(); }
                    seen.insert(dedup_key);
                }
            }
            None => return Json(json!({"status":"error","message":"bad signature"})),
        }
    } else if let (Some(key), Some(sig_b64)) = (key_opt, sig_opt) {
        let nonce = req.nonce.unwrap_or(0);
        let msg = format!("mint|{}|{}|{}|{}", req.proposer, req.to, req.amount, nonce);
        if b64_decode(sig_b64)
            .ok()
            .and_then(|b| Ed25519Signature::from_bytes(&b).ok())
            .and_then(|sig| key.verify(msg.as_bytes(), &sig).ok())
            .is_some()
        {
            let dedup_key = format!("{}:{}", req.proposer, nonce);
            let mut seen = state.seen_nonces.write().await;
            if nonce != 0 {
                if seen.contains(&dedup_key) { return Json(json!({"status":"error","message":"replay"})); }
                if seen.len() > 10_000 { seen.clear(); }
                seen.insert(dedup_key);
            }
        } else {
            return Json(json!({"status":"error","message":"bad signature"}));
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
    let key_opt = state.authority_keys.get(&req.proposer);
    let sig_opt = req.signature.as_ref();
    if state.require_sigs {
        let Some(key) = key_opt else { return Json(json!({"status":"error","message":"unknown authority"})); };
        let Some(sig_b64) = sig_opt else { return Json(json!({"status":"error","message":"missing signature"})); };
        let nonce = req.nonce.unwrap_or(0);
        let msg = format!("transfer|{}|{}|{}|{}|{}", req.proposer, req.from, req.to, req.amount, nonce);
        match b64_decode(sig_b64)
            .ok()
            .and_then(|b| Ed25519Signature::from_bytes(&b).ok())
            .and_then(|sig| key.verify(msg.as_bytes(), &sig).ok()) {
            Some(()) => {
                let dedup_key = format!("{}:{}", req.proposer, nonce);
                let mut seen = state.seen_nonces.write().await;
                if nonce != 0 {
                    if seen.contains(&dedup_key) { return Json(json!({"status":"error","message":"replay"})); }
                    if seen.len() > 10_000 { seen.clear(); }
                    seen.insert(dedup_key);
                }
            }
            None => return Json(json!({"status":"error","message":"bad signature"})),
        }
    } else if let (Some(key), Some(sig_b64)) = (key_opt, sig_opt) {
        let nonce = req.nonce.unwrap_or(0);
        let msg = format!("transfer|{}|{}|{}|{}|{}", req.proposer, req.from, req.to, req.amount, nonce);
        if b64_decode(sig_b64)
            .ok()
            .and_then(|b| Ed25519Signature::from_bytes(&b).ok())
            .and_then(|sig| key.verify(msg.as_bytes(), &sig).ok())
            .is_some()
        {
            let dedup_key = format!("{}:{}", req.proposer, nonce);
            let mut seen = state.seen_nonces.write().await;
            if nonce != 0 {
                if seen.contains(&dedup_key) { return Json(json!({"status":"error","message":"replay"})); }
                if seen.len() > 10_000 { seen.clear(); }
                seen.insert(dedup_key);
            }
        } else {
            return Json(json!({"status":"error","message":"bad signature"}));
        }
    }
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

fn load_authorities() -> HashSet<String> {
    // Prefer file if provided
    let file_path = env::var("DEVCOIN_AUTHORITIES_FILE").ok();
    let mut set: HashSet<String> = HashSet::new();
    if let Some(fp) = file_path {
        if let Ok(data) = fs::read_to_string(fp) {
            for line in data.lines() {
                let v = line.trim();
                if !v.is_empty() { set.insert(v.to_string()); }
            }
        }
    }
    // Merge from env list
    if let Ok(val) = env::var("DEVCOIN_AUTHORITIES") {
        for v in val.split(',') {
            let v = v.trim();
            if !v.is_empty() { set.insert(v.to_string()); }
        }
    }
    // In production, require explicit authorities to avoid insecure defaults
    let require = env::var("DEVCOIN_REQUIRE_AUTHORITIES").map(|v| {
        matches!(v.to_ascii_lowercase().as_str(), "1"|"true"|"yes")
    }).unwrap_or(false) || matches!(env::var("RUST_ENV").ok().as_deref(), Some("production"))
      || matches!(env::var("NODE_ENV").ok().as_deref(), Some("production"));
    if set.is_empty() {
        if require {
            panic!("No authorities configured: set DEVCOIN_AUTHORITIES or DEVCOIN_AUTHORITIES_FILE");
        } else {
            // Dev-friendly default
            set.insert("authority1".to_string());
        }
    }
    set
}

fn load_authority_keys() -> (HashMap<String, Ed25519PublicKey>, bool) {
    let mut keys: HashMap<String, Ed25519PublicKey> = HashMap::new();
    let mut added = 0usize;
    if let Ok(path) = env::var("DEVCOIN_AUTHORITIES_KEYS") {
        if let Ok(contents) = fs::read_to_string(&path) {
            for line in contents.lines() {
                // drop inline comments and trim
                let mut line = line;
                if let Some((head, _)) = line.split_once('#') { line = head; }
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                // Split on the FIRST separator only to preserve base64 '=' padding
                let (id, key_str_opt): (String, Option<&str>) = if let Some((a, b)) = line.split_once('=') {
                    (a.trim().to_string(), Some(b.trim()))
                } else if let Some((a, b)) = line.split_once(':') {
                    (a.trim().to_string(), Some(b.trim()))
                } else {
                    // Fallback: split on whitespace into two parts
                    let mut it = line.split_whitespace();
                    let a = it.next().unwrap_or("").trim().to_string();
                    let b = it.next();
                    (a, b)
                };
                let Some(key_str) = key_str_opt else {
                    tracing::warn!(file = %path, line = %line, "missing key value in authority keys line");
                    continue;
                };
                if id.is_empty() { tracing::warn!(file = %path, line = %line, "empty authority id"); continue; }
                if let Some(pk) = parse_pubkey(key_str) {
                    keys.insert(id.clone(), pk);
                    added += 1;
                    info!(file = %path, authority = %id, "loaded authority public key");
                } else {
                    tracing::warn!(file = %path, line = %line, "failed to parse authority public key");
                }
            }
        } else {
            tracing::warn!(file = %path, "failed to read DEVCOIN_AUTHORITIES_KEYS file");
        }
    }
    let require = env::var("DEVCOIN_REQUIRE_SIGS").map(|v| matches!(v.to_ascii_lowercase().as_str(), "1"|"true"|"yes" )).unwrap_or(false);
    info!(keys = added, require_sigs = require, "authority key loading complete");
    (keys, require && added>0 || require)
}

fn parse_pubkey(s: &str) -> Option<Ed25519PublicKey> {
    // Try base64, then hex
    if let Ok(b) = b64_decode(s) {
        if b.len() != 32 {
            tracing::warn!(len = b.len(), "decoded base64 pubkey has unexpected length");
        }
        return Ed25519PublicKey::from_bytes(&b).ok();
    }
    if let Ok(b) = hex::decode(s) {
        if b.len() != 32 {
            tracing::warn!(len = b.len(), "decoded hex pubkey has unexpected length");
        }
        return Ed25519PublicKey::from_bytes(&b).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_and_transfer() {
    let authorities: HashSet<String> = ["authority1".to_string()].into_iter().collect();
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
