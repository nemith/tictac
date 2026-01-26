use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::Result;

use crate::packet::{
    obfuscate, AuthenReply, AuthenReplyFlags, AuthenStart, AuthenStatus, Flags, Packet,
    PacketBody, PacketType, Version,
};

struct Session {
    seq: u8,
    username: Option<Vec<u8>>,
}

pub struct Connection {
    stream: TcpStream,
    sessions: HashMap<u32, Session>,
    secret_key: Vec<u8>,
    out_buf: Vec<u8>,
}

impl Connection {
    pub fn new(stream: TcpStream, secret_key: &[u8]) -> Self {
        Self {
            stream,
            sessions: HashMap::new(),
            secret_key: secret_key.to_vec(),
            out_buf: Vec::with_capacity(4096),
        }
    }

    pub fn handle(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];

        loop {
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);

            while let Some(pkt) = Packet::decode(&mut buf, &self.secret_key)? {
                let consumed = pkt.len();

                println!(
                    "Got packet: ver={:?} type={:?} seq={} flags={:?} session={} body_len={}",
                    pkt.version, pkt.ptype, pkt.seq, pkt.flags, pkt.session_id, pkt.body.len()
                );

                match pkt.ptype {
                    PacketType::Authen => {
                        let session = self.sessions.get(&pkt.session_id);

                        if session.is_none() && pkt.seq == 1 {
                            // New session with AuthenStart
                            let start = AuthenStart::decode(pkt.body)?;
                            println!(
                                "  AuthenStart: action={:?} user={:?}",
                                start.action,
                                String::from_utf8_lossy(start.user)
                            );

                            // For now, just pass everyone
                            let reply = AuthenReply {
                                status: AuthenStatus::Pass,
                                flags: AuthenReplyFlags::empty(),
                                server_msg: b"",
                                data: b"",
                            };

                            self.send_reply(&pkt, &reply)?;
                        } else if let Some(_session) = session {
                            // Existing session, expect AuthenContinue
                            todo!("handle AuthenContinue");
                        } else {
                            // Invalid state - no session but seq != 1
                            eprintln!(
                                "Invalid packet: no session for id={} but seq={}",
                                pkt.session_id, pkt.seq
                            );
                        }
                    }
                    PacketType::Author => todo!(),
                    PacketType::Acct => todo!(),
                }

                buf.drain(..consumed);
            }
        }
    }

    fn send_reply(&mut self, pkt: &Packet, body: &impl PacketBody) -> Result<()> {
        let body_len = body.len();
        let total_len = Packet::HEADER_LENGTH + body_len;

        self.out_buf.clear();
        self.out_buf.resize(total_len, 0);

        let reply_pkt = Packet {
            version: Version {
                major: Version::MAJOR_VER,
                minor: Version::MINOR_VER_DEFAULT,
            },
            ptype: pkt.ptype,
            seq: pkt.seq + 1,
            flags: pkt.flags,
            session_id: pkt.session_id,
            body: &mut [],
        };

        body.encode(&mut self.out_buf[Packet::HEADER_LENGTH..]);
        reply_pkt.encode_header(&mut self.out_buf, body_len as u32);

        if !pkt.flags.contains(Flags::UNENCRYPTED) {
            obfuscate(
                &mut self.out_buf[Packet::HEADER_LENGTH..],
                pkt.session_id,
                &self.secret_key,
                reply_pkt.version.encode(),
                reply_pkt.seq,
            );
        }

        self.stream.write_all(&self.out_buf)?;
        Ok(())
    }
}

pub fn run(addr: &str, secret_key: &[u8]) -> Result<()> {
    let listener = TcpListener::bind(addr)?;

    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let key = secret_key.to_vec();
            std::thread::spawn(move || {
                let mut conn = Connection::new(s, &key);
                conn.handle().ok();
            });
        }
    }

    Ok(())
}
