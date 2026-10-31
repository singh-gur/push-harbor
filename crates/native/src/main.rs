//! Pushharbor native server (axum + tokio + SQLite or PostgreSQL) for containers, VPS and
//! Kubernetes.

mod adapters;
mod config;
mod server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

use crate::adapters::{
    MemoryRateLimiter, MemoryTokenCache, NativeCrypto, NativeRateLimiter, ReqwestHttp,
    SqlRateLimiter, SqlStore, now, purge_expired,
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

    let (pool, postgres) = open_database(&config.database_url).await;
    let migrator = if postgres {
        sqlx::migrate!("migrations/postgres")
    } else {
        sqlx::migrate!("migrations/sqlite")
    };
    // Concurrent instances are safe: sqlx takes a database lock while migrating.
    migrator
        .run(&pool)
        .await
        .unwrap_or_else(|e| fail(&format!("database migration failed: {e}")));

    let purge_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PURGE_EVERY);
        loop {
            interval.tick().await;
            if let Err(e) = purge_expired(&purge_pool, postgres, now()).await {
                tracing::warn!(error = %e, "purging expired rows failed");
            }
        }
    });

    let limiter = if postgres {
        NativeRateLimiter::Shared(SqlRateLimiter(pool.clone()))
    } else {
        NativeRateLimiter::Memory(MemoryRateLimiter::default())
    };

    let state = Arc::new(AppState {
        origin: config.origin.clone(),
        limits: config.limits,
        trust_proxy: config.trust_proxy,
        account: config.fcm,
        store: SqlStore(pool),
        limiter,
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

/// `sqlite://<path>` (created if missing, WAL) or `postgres://…`. Returns the pool and whether it
/// is PostgreSQL.
async fn open_database(url: &str) -> (AnyPool, bool) {
    sqlx::any::install_default_drivers();
    let postgres = url.starts_with("postgres://") || url.starts_with("postgresql://");
    let url = match url.strip_prefix("sqlite://") {
        Some(_) if url.contains('?') => url.to_owned(),
        Some(_) => format!("{url}?mode=rwc"),
        None if postgres => url.to_owned(),
        None => fail("PUSHHARBOR_DATABASE_URL must start with sqlite:// or postgres://"),
    };
    let pool = AnyPoolOptions::new()
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if !postgres {
                    // WAL lets reads run during writes; sqlx's busy timeout (5 s) covers the rest.
                    sqlx::query("PRAGMA journal_mode = WAL")
                        .execute(conn)
                        .await?;
                }
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap_or_else(|e| fail(&format!("can't open database: {e}")));
    (pool, postgres)
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
