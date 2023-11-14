use std::io::Cursor;
use std::str;
use std::string::FromUtf8Error;

use bitflags::bitflags;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BytesMut};
use digest::generic_array::GenericArray;
use digest::typenum::U16;
use md5::{Digest, Md5};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;

#[derive(Debug)]
enum PacketBody {
    AuthenStart {
        action: AuthenAction,
        priv_lvl: u8,
        authen_type: AuthenType,
        authen_service: AuthenService,
        user: String,
        port: String,
        rem_addr: String,
        data: String,
    },
    AuthenReply {
        status: AuthenStatus,
        flags: ReplyFlags,
        server_msg: String,
        data: String,
    },
    AuthenContinue {
        flags: ContinueFlags,
        user_msg: String,
        data: String,
    },
    //AuthorReq
    //AuthorResp
    //AcctReq
    //ActResp
}

#[derive(Debug)]
#[repr(u8)]
enum HeaderType {
    Authen = 0x01, // TAC_PLUS_AUTHEN
    Author = 0x02, // TAC_PLUS_AUTHOR
    Acct = 0x03,   // TAC_PLUS_ACCT
}

impl TryFrom<u8> for HeaderType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(HeaderType::Authen),
            0x02 => Ok(HeaderType::Author),
            0x03 => Ok(HeaderType::Acct),
            _ => Err(Error::InvalidPacket(format!("invalid packet type {value}"))),
        }
    }
}

enum PacketType {
    AuthenStart,
    AuthenReply,
    AuthenContinue,
    AuthorReq,
    AuthorReply,
    AcctReq,
    AcctReply,
}

impl PacketType {
    fn new(packet_type: HeaderType, seq_no: u8) -> Self {
        // requests (from client to server) start at 1 and are always odd
        // responses (from server to client) starts at 2 and are always even
        let is_odd = seq_no % 2 != 0;
        match (packet_type, is_odd) {
            (HeaderType::Authen, true) => {
                if seq_no == 1 {
                    PacketType::AuthenStart
                } else {
                    PacketType::AuthenContinue
                }
            }
            (HeaderType::Authen, false) => PacketType::AuthenReply,
            (HeaderType::Author, true) => PacketType::AuthorReq,
            (HeaderType::Author, false) => PacketType::AuthenReply,
            (HeaderType::Acct, true) => PacketType::AcctReq,
            (HeaderType::Acct, false) => PacketType::AcctReply,
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct Flags: u8 {
        const UNENCRYPTED = 0x01; // TAC_PLUS_UNENCRYPTED_FLAG
        const SINGLE_CONNECT = 0x04; // TAC_PLUS_SINGLE_CONNECT_FLAG
    }
}

#[derive(Debug)]
#[repr(u8)]
enum AuthenAction {
    Login = 0x01,    // TAC_PLUS_AUTHEN_LOGIN = 0x01,
    Chpass = 0x02,   //TAC_PLUS_AUTHEN_CHPASS = 0x02,
    SendAuth = 0x04, // TAC_PLUS_AUTHEN_SENDAUTH = 0x04,
}

impl TryFrom<u8> for AuthenAction {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AuthenAction::Login),
            0x02 => Ok(AuthenAction::Chpass),
            0x04 => Ok(AuthenAction::SendAuth),
            _ => Err(Error::InvalidPacket(format!(
                "invalid authenication action {value}"
            ))),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
enum AuthenType {
    Ascii = 0x01,    // TAC_PLUS_AUTHEN_TYPE_ASCII
    Pap = 0x02,      // TAC_PLUS_AUTHEN_TYPE_PAP
    Chap = 0x03,     // TAC_PLUS_AUTHEN_TYPE_CHAP
    Mschap = 0x05,   // TAC_PLUS_AUTHEN_TYPE_MSCHAP
    Mschapv2 = 0x06, // TAC_PLUS_AUTHEN_TYPE_MSCHAPV2
}

impl TryFrom<u8> for AuthenType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AuthenType::Ascii),
            0x02 => Ok(AuthenType::Pap),
            0x03 => Ok(AuthenType::Chap),
            0x05 => Ok(AuthenType::Mschap),
            0x06 => Ok(AuthenType::Mschapv2),
            _ => Err(Error::InvalidPacket(format!(
                "invalid authenication type {value}"
            ))),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
enum AuthenService {
    None = 0x00,    // TAC_PLUS_AUTHEN_SVC_NONE
    Login = 0x01,   // TAC_PLUS_AUTHEN_SVC_LOGIN
    Enable = 0x02,  // TAC_PLUS_AUTHEN_SVC_ENABLE
    PPP = 0x03,     // TAC_PLUS_AUTHEN_SVC_PPP
    Pt = 0x05,      // TAC_PLUS_AUTHEN_SVC_PT
    Rcmd = 0x06,    // TAC_PLUS_AUTHEN_SVC_RCMD
    X25 = 0x07,     // TAC_PLUS_AUTHEN_SVC_X25
    Nasi = 0x08,    // TAC_PLUS_AUTHEN_SVC_NASI
    Fwproxy = 0x09, // TAC_PLUS_AUTHEN_SVC_FWPROXY
}

impl TryFrom<u8> for AuthenService {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AuthenService::None),
            0x01 => Ok(AuthenService::Login),
            0x02 => Ok(AuthenService::Enable),
            0x03 => Ok(AuthenService::PPP),
            0x05 => Ok(AuthenService::Pt),
            0x06 => Ok(AuthenService::Rcmd),
            0x07 => Ok(AuthenService::X25),
            0x08 => Ok(AuthenService::Nasi),
            0x09 => Ok(AuthenService::Fwproxy),
            _ => Err(Error::InvalidPacket(format!(
                "invalid authenication service {value}"
            ))),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
enum AuthenStatus {
    Pass = 0x01,    // TAC_PLUS_AUTHEN_STATUS_PASS
    Fail = 0x02,    // TAC_PLUS_AUTHEN_STATUS_FAIL
    GetData = 0x03, // TAC_PLUS_AUTHEN_STATUS_GETDATA
    GetUser = 0x04, // TAC_PLUS_AUTHEN_STATUS_GETUSER
    GetPass = 0x05, // TAC_PLUS_AUTHEN_STATUS_GETPASS
    Restart = 0x06, // TAC_PLUS_AUTHEN_STATUS_RESTART
    Error = 0x07,   // TAC_PLUS_AUTHEN_STATUS_ERROR
    Follow = 0x21,  // TAC_PLUS_AUTHEN_STATUS_FOLLOW
}

impl TryFrom<u8> for AuthenStatus {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, <AuthenStatus as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(AuthenStatus::Pass),
            0x02 => Ok(AuthenStatus::Fail),
            0x03 => Ok(AuthenStatus::GetData),
            0x04 => Ok(AuthenStatus::GetUser),
            0x05 => Ok(AuthenStatus::GetPass),
            0x06 => Ok(AuthenStatus::Restart),
            0x07 => Ok(AuthenStatus::Error),
            0x21 => Ok(AuthenStatus::Follow),
            _ => Err(Error::InvalidPacket(format!(
                "invalid authenication status {value}"
            ))),
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct ReplyFlags: u8 {
        const NOECHO = 0x01;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct ContinueFlags: u8 {
        const CONTINUE_FLAG_ABORT = 0x01;
    }
}

#[derive(Debug)]
struct Header {
    version: u8,
    seq_no: u8,
    flags: Flags,
    session_id: u32,
}

#[derive(Debug)]
pub struct Packet {
    header: Header,
    body: PacketBody,
}

const HEADER_LENGTH: usize = 12;

/// recommended value in RFC8907 Section 4.1
pub const DEFAULT_MAX_PACKET_LEN: u32 = 65536;

pub struct TacacsCodec {
    max_pkt_length: u32,
    secret_key: String,
}

impl TacacsCodec {
    pub fn new(secret_key: &str, max_pkt_length: u32) -> Self {
        TacacsCodec {
            max_pkt_length,
            secret_key: secret_key.into(),
        }
    }
}

impl Encoder<&Packet> for TacacsCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: &Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Decoder for TacacsCodec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buf_len = src.len();

        // check to see if we have read enough to parse the header.
        if buf_len < HEADER_LENGTH {
            return Ok(None);
        }

        let mut c = Cursor::new(&src);
        let version = c.read_u8().unwrap();
        let typ: HeaderType = c.read_u8().unwrap().try_into()?;
        let seq_no = c.read_u8().unwrap();
        let flags = Flags::from_bits(c.read_u8().unwrap()).unwrap(); // read to flags
        let session_id = c.read_u32::<NetworkEndian>().unwrap();
        let len = c.read_u32::<NetworkEndian>().unwrap() as usize;

        if buf_len > self.max_pkt_length as usize {
            return Err(Error::InvalidPacket("too large".to_owned()));
        }

        // check to see if we have enough data for the full body
        if buf_len < len as usize {
            // reserve space for the rest of the packet body
            src.reserve(HEADER_LENGTH + len as usize - src.len());
            return Ok(None);
        }
        src.advance(HEADER_LENGTH as usize);

        let header = Header {
            version,
            seq_no,
            flags,
            session_id,
        };
        dbg!(&header);
        dbg!(&typ);

        // deobfuscate if we need to
        if !flags.contains(Flags::UNENCRYPTED) {
            obfuscate(src, session_id, &self.secret_key, version, seq_no);
        }

        match PacketType::new(typ, seq_no) {
            // Authentication START packet
            //  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |    action      |    priv_lvl    |  authen_type   | authen_service |
            // +----------------+----------------+----------------+----------------+
            // |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
            // +----------------+----------------+----------------+----------------+
            // |    user ...
            // +----------------+----------------+----------------+----------------+
            // |    port ...
            // +----------------+----------------+----------------+----------------+
            // |    rem_addr ...
            // +----------------+----------------+----------------+----------------+
            // |    data...
            // +----------------+----------------+----------------+----------------+
            PacketType::AuthenStart => {
                let mut r = src.reader();
                let action: AuthenAction = r.read_u8().unwrap().try_into()?;
                let priv_lvl = r.read_u8().unwrap();
                let authen_type: AuthenType = r.read_u8().unwrap().try_into()?;
                let authen_service: AuthenService = r.read_u8().unwrap().try_into()?;
                let user_len = r.read_u8().unwrap();
                let port_len = r.read_u8().unwrap();
                let rem_addr_len = r.read_u8().unwrap();
                let data_len = r.read_u8().unwrap();
                let user = read_string(src, user_len.into()).unwrap();
                let port = read_string(src, port_len.into()).unwrap();
                let rem_addr = read_string(src, rem_addr_len.into()).unwrap();
                let data = read_string(src, data_len.into()).unwrap();
                Ok(Some(Packet {
                    header,
                    body: PacketBody::AuthenStart {
                        action,
                        priv_lvl,
                        authen_type,
                        authen_service,
                        user,
                        port,
                        rem_addr,
                        data,
                    },
                }))
            }
            // Authentication REPLY packet
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |     status     |      flags     |        server_msg_len           |
            // +----------------+----------------+----------------+----------------+
            // |           data_len              |        server_msg ...
            // +----------------+----------------+----------------+----------------+
            // |           data ...
            // +----------------+----------------+
            PacketType::AuthenReply => {
                let mut r = src.reader();
                let status: AuthenStatus = r.read_u8().unwrap().try_into()?;
                let reply_flags = ReplyFlags::from_bits(r.read_u8().unwrap()).unwrap();
                let server_msg_len = r.read_u8().unwrap();
                let data_len = r.read_u8().unwrap();
                let server_msg = read_string(src, server_msg_len.into()).unwrap();
                let data = read_string(src, data_len.into()).unwrap();
                Ok(Some(Packet {
                    header,
                    body: PacketBody::AuthenReply {
                        status,
                        flags: reply_flags,
                        server_msg,
                        data,
                    },
                }))
            }
            // Authentication CONTINUE packet
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |          user_msg len           |            data_len             |
            // +----------------+----------------+----------------+----------------+
            // |     flags      |  user_msg ...
            // +----------------+----------------+----------------+----------------+
            // |    data ...
            // +----------------+
            PacketType::AuthenContinue => {
                let mut r = src.reader();
                let user_msg_len = r.read_u16::<NetworkEndian>().unwrap();
                let data_len = r.read_u16::<NetworkEndian>().unwrap();
                let bits = r.read_u8().unwrap();
                dbg!(&bits);
                let flags = ContinueFlags::from_bits(bits).unwrap();
                let user_msg = read_string(src, user_msg_len.into()).unwrap();
                let data = read_string(src, data_len.into()).unwrap();
                Ok(Some(Packet {
                    header,
                    body: PacketBody::AuthenContinue {
                        flags,
                        user_msg,
                        data,
                    },
                }))
            }
            // The Authorization REQUEST Packet Body
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |  authen_method |    priv_lvl    |  authen_type   | authen_service |
            // +----------------+----------------+----------------+----------------+
            // |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
            // +----------------+----------------+----------------+----------------+
            // |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
            // +----------------+----------------+----------------+----------------+
            // |   user ...
            // +----------------+----------------+----------------+----------------+
            // |   port ...
            // +----------------+----------------+----------------+----------------+
            // |   rem_addr ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_1 ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_2 ...
            // +----------------+----------------+----------------+----------------+
            // |   ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_N ...
            // +----------------+----------------+----------------+----------------+
            PacketType::AuthorReq => {
                todo!()
            }
            // The Authorization REPLY Packet Body
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |    status      |     arg_cnt    |         server_msg len          |
            // +----------------+----------------+----------------+----------------+
            // +            data_len             |    arg_1_len   |    arg_2_len   |
            // +----------------+----------------+----------------+----------------+
            // |      ...       |   arg_N_len    |         server_msg ...
            // +----------------+----------------+----------------+----------------+
            // |   data ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_1 ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_2 ...
            // +----------------+----------------+----------------+----------------+
            // |   ...
            // +----------------+----------------+----------------+----------------+
            // |   arg_N ...
            // +----------------+----------------+----------------+----------------+
            PacketType::AuthorReply => {
                todo!()
            }
            // The Account REQUEST Packet Body
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            //+----------------+----------------+----------------+----------------+
            //|      flags     |  authen_method |    priv_lvl    |  authen_type   |
            //+----------------+----------------+----------------+----------------+
            //| authen_service |    user_len    |    port_len    |  rem_addr_len  |
            //+----------------+----------------+----------------+----------------+
            //|    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
            //+----------------+----------------+----------------+----------------+
            //|   arg_N_len    |    user ...
            //+----------------+----------------+----------------+----------------+
            //|   port ...
            //+----------------+----------------+----------------+----------------+
            //|   rem_addr ...
            //+----------------+----------------+----------------+----------------+
            //|   arg_1 ...
            //+----------------+----------------+----------------+----------------+
            //|   arg_2 ...
            //+----------------+----------------+----------------+----------------+
            //|   ...
            //+----------------+----------------+----------------+----------------+
            //|   arg_N ...
            //+----------------+----------------+----------------+----------------+
            PacketType::AcctReq => {
                todo!()
            }
            // The Accounting REPLY Packet Body
            // 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
            // +----------------+----------------+----------------+----------------+
            // |         server_msg len          |            data_len             |
            // +----------------+----------------+----------------+----------------+
            // |     status     |         server_msg ...
            // +----------------+----------------+----------------+----------------+
            // |     data ...
            // +----------------+
            PacketType::AcctReply => {
                todo!()
            }
        }
    }
}

/// obfuscate implements the "encryption" for TACACS as defied in RFC8907
/// section 4.5.  It will mutate the bytes in place and is bidrectional.
fn obfuscate(buf: &mut BytesMut, session_id: u32, secret_key: &str, version: u8, seq: u8) {
    let mut hasher = Md5::new();

    // store the last hash used as it is pontentially needed for the next chunk.
    // However on first iteration this should not be set so it is initialized to
    // None.
    // a enericArray is used here as it is required for `finalize_into_reset`.
    let mut hash: Option<GenericArray<u8, U16>> = None;

    // process each 16 byte chunk of
    for chunk in buf.chunks_mut(16) {
        // calculate the next hash using the session_id, secret_key, version,
        // seq, and the last hash (if present)
        hasher
            .write_u32::<NetworkEndian>(session_id)
            .expect("write to hash should always succeed");
        hasher.update(secret_key);
        hasher.update(&[version, seq]);

        // add the last hash into (if present, i.e: not the first iteration and
        // store it for next loop)
        if let Some(hash) = hash.as_mut() {
            hasher.update(&hash);
            hasher.finalize_into_reset(hash);
        } else {
            hash = Some(hasher.finalize_reset());
        }

        // (de)obfusicate the body by XORing the bytes in the hash with the
        // bytes in the current 16 byte chunk.
        chunk
            .iter_mut()
            .zip(hash.expect("hash should never be None"))
            .for_each(|(v, h)| *v ^= h);
    }
}

/// read_string will read in a string from the underlying BytesMut advancing the
/// buffer.
fn read_string(buf: &mut BytesMut, length: usize) -> Result<String, FromUtf8Error> {
    if buf.len() < length {
        panic!("buffer not large enough")
    }

    let s = &buf[..length];
    match String::from_utf8(s.to_vec()) {
        Ok(string) => {
            buf.advance(length);
            Ok(string)
        }
        Err(err) => Err(err),
    }
}

mod test {
    use super::*;

    #[test]
    fn test_decode() {}

    #[test]
    fn test_obfuscate() {
        let input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur in facilisis metus, in tempor sem.";
        let mut buf = input.into();
        let encrypted: &[u8] = &[
            0x12, 0xc2, 0xf8, 0x2f, 0xe1, 0xfb, 0x9f, 0xe8, 0x42, 0x95, 0x41, 0x93, 0x0b, 0x67,
            0xa5, 0x16, 0x65, 0x97, 0x18, 0x6e, 0xfd, 0x83, 0x1a, 0x16, 0xcd, 0x75, 0x05, 0x07,
            0xa5, 0x41, 0xf0, 0x1b, 0x74, 0x3c, 0x84, 0xe6, 0xf7, 0x81, 0x35, 0xfc, 0x4e, 0xc6,
            0xb6, 0x76, 0x67, 0x00, 0x76, 0x1c, 0x02, 0x34, 0x4b, 0x62, 0x02, 0xe2, 0xb7, 0x0d,
            0xd4, 0xcd, 0xd7, 0x70, 0xb2, 0xc7, 0x07, 0x2d, 0x0d, 0xbf, 0x15, 0x44, 0xd9, 0x6f,
            0x97, 0x5c, 0x50, 0xca, 0xfb, 0x7c, 0x96, 0x4a, 0xcb, 0xe7, 0xfd, 0xc2, 0xdc, 0xc3,
            0x6e, 0xc5, 0x99, 0xd5, 0xcd, 0x4e, 0x10, 0x5b, 0x7c, 0xd8, 0x05, 0x1a, 0xae, 0xda,
            0x92, 0xb1, 0xe4,
        ];

        obfuscate(&mut buf, 1581998937, &"test", 0xc << 4, 1);
        assert_eq!(buf, encrypted);

        // "decrypting" is the same operation.
        obfuscate(&mut buf, 1581998937, &"test", 0xc << 4, 1);
        assert_eq!(buf, input);
    }
}
