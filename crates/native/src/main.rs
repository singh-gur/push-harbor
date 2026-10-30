//! Pushharbor native server (axum + tokio + SQLite) for containers, VPS and Kubernetes.

mod adapters;
mod config;
mod server;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::adapters::{
    MemoryRateLimiter, MemoryTokenCache, NativeCrypto, ReqwestHttp, SqliteStore, now, purge_expired,
};
use crate::config::{Config, USAGE};
use crate::server::{AppState, router};

const PURGE_EVERY: Duration = Duration::from_secs(600);

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }
    tracing_subscriber::fmt()
        // Plain text in containers/files: color codes would garble log pipelines.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("configuration error: {e}\n\n{USAGE}");
        std::process::exit(2);
    });

    let options = SqliteConnectOptions::from_str(&config.database_url)
        .unwrap_or_else(|e| fail(&format!("PUSHHARBOR_DATABASE_URL: {e}")))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .unwrap_or_else(|e| fail(&format!("can't open database: {e}")));
    sqlx::migrate!()
        .run(&pool)
        .await
        .unwrap_or_else(|e| fail(&format!("database migration failed: {e}")));

    let purge_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PURGE_EVERY);
        loop {
            interval.tick().await;
            if let Err(e) = purge_expired(&purge_pool, now()).await {
                tracing::warn!(error = %e, "purging expired rows failed");
            }
        }
    });

    let state = Arc::new(AppState {
        origin: config.origin.clone(),
        limits: config.limits,
        trust_proxy: config.trust_proxy,
        account: config.fcm,
        store: SqliteStore(pool),
        limiter: MemoryRateLimiter::default(),
        crypto: NativeCrypto::default(),
        http: ReqwestHttp::new(config.provider_timeout),
        cache: MemoryTokenCache::default(),
    });
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .unwrap_or_else(|e| fail(&format!("can't listen on {}: {e}", config.listen)));
    tracing::info!(listen = %config.listen, origin = %config.origin, "pushharbor-native ready");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|e| fail(&format!("server error: {e}")));
    tracing::info!("shut down");
}

fn fail(message: &str) -> ! {
    tracing::error!("{message}");
    eprintln!("{message}");
    std::process::exit(1);
}

async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}
