//! Command-line adapter for the reusable Confido client library.

#[tokio::main]
async fn main() -> confido_client::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let code = confido_client::run_cli(&args).await?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
