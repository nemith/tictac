#[tokio::main]
async fn main() {
    let server = tictac::server::Server {};
    server.start("0.0.0.0:49").await;
}
