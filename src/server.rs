use futures::stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use crate::packet;
use crate::packet::TacacsCodec;

pub struct Server {}

impl Server {
    pub async fn start(&self, addr: &str) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                handle(socket).await;
            });
        }
    }
}

pub struct Connection {}

async fn handle(stream: TcpStream) {
    let codec = TacacsCodec::new("foobar", packet::DEFAULT_MAX_PACKET_LEN);
    let mut framed = Framed::new(stream, codec);
    while let Some(msg) = framed.next().await {
        match msg {
            Ok(msg) => {
                dbg!(msg);
                framed.send(packet::Packet { header: Header {} })
            }
            Err(err) => {
                println!("{}", err);
                break;
            }
        }
    }
}
