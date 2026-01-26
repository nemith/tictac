use anyhow::Result;

mod packet;
mod server;

fn main() -> Result<()> {
    server::run("127.0.0.1:4949", b"test")
}
