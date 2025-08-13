use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};

fn wait_port(addr: &str, attempts: u32) {
    for _ in 0..attempts {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("port not listening: {}", addr);
}

#[test]
fn e2e_health_mint_balance() {
    // pick a free port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{}", port);
    let token = "itest-token".to_string();
    let data_dir = tempfile::tempdir().unwrap();

    // Run the compiled binary directly for speed/stability
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/devcoin-node");
    let mut cmd = Command::new(bin);
    cmd.env("RUST_LOG", "info")
        .env("DEVCOIN_ADDR", &addr)
        .env("DEVCOIN_AUTHORITIES", "authority1")
        .env("DEVCOIN_DATA_DIR", data_dir.path())
        .env("DEVCOIN_MINT_TOKEN", &token)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("start node");
    wait_port(&addr, 300); // up to ~30s

    // health
    let health = ureq::get(&format!("http://{}/health", addr))
        .call()
        .unwrap();
    assert_eq!(health.status(), 200);

    // mint
    let body = serde_json::json!({"proposer":"authority1","to":"itest","amount":5});
    let mint = ureq::post(&format!("http://{}/mint", addr))
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", token))
        .send_string(&body.to_string())
        .unwrap();
    assert_eq!(mint.status(), 200, "mint status: {}", mint.status());

    // balance
    let bal: serde_json::Value = ureq::get(&format!("http://{}/balance/{}", addr, "itest"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(bal["balance"].as_u64().unwrap_or(0), 5);

    let _ = child.kill();
    let _ = child.wait();
}
