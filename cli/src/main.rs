//! Command-line adapter for the reusable Confido client library.

mod commands;

#[tokio::main]
async fn main() -> confido_client::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let code = commands::run_cli(&args).await?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
