#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::perf)]

use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .init();
}
