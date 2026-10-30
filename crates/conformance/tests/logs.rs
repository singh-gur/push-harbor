//! Runs after the `conformance` test binary: no FID, nonce, payload, VAPID token, sender key or
//! endpoint ID the suite used may appear in the relay's log file (`RELAY_LOG`).

#[test]
fn logs_contain_no_secrets() {
    let (Ok(log_path), Ok(secrets)) = (
        std::env::var("RELAY_LOG"),
        std::fs::read_to_string(pushharbor_conformance::secrets_file()),
    ) else {
        eprintln!("RELAY_LOG or the secrets file is missing: skipping log check");
        return;
    };
    let log =
        std::fs::read_to_string(&log_path).unwrap_or_else(|e| panic!("can't read {log_path}: {e}"));
    let leaked: Vec<&str> = secrets
        .lines()
        .filter(|s| s.len() >= 8 && log.contains(*s))
        .collect();
    assert!(
        leaked.is_empty(),
        "{} secret value(s) found in {log_path}, e.g. {:.12}…",
        leaked.len(),
        leaked[0]
    );
}
