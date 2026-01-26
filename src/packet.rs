use bitflags::bitflags;
use bytes::{Buf, BufMut};
use num_enum::TryFromPrimitive;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("invalid value {0:#x} for {1}")]
    InvalidValue(u8, &'static str),
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("bad body length (expected {expected}, got {actual}) - possible key mismatch")]
    BadBodyLen { expected: usize, actual: usize },
}

pub trait PacketBody {
    fn len(&self) -> usize;
    fn encode(&self, buf: &mut [u8]);
}

#[derive(Debug, Clone, Copy)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    pub const MAJOR_VER: u8 = 0x0C;
    pub const MINOR_VER_DEFAULT: u8 = 0x00;
    pub const MINOR_VER_ONE: u8 = 0x01;

    pub fn decode(byte: u8) -> Self {
        Self {
            major: byte >> 4,
            minor: byte & 0x0F,
        }
    }

    pub fn encode(&self) -> u8 {
        (self.major << 4) | (self.minor & 0x0F)
    }
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum PacketType {
    Authen = 0x01,
    Author = 0x02,
    Acct = 0x03,
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Flags: u8 {
        const UNENCRYPTED = 0x01;
        const SINGLE_CONNECT = 0x04;
    }
}

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |major  | minor  |                |                |                |
// |version| version|      type      |     seq_no     |   flags        |
// +----------------+----------------+----------------+----------------+
// |                            session_id                             |
// +----------------+----------------+----------------+----------------+
// |                              length                               |
// +----------------+----------------+----------------+----------------+
pub struct Packet<'a> {
    pub version: Version,
    pub ptype: PacketType,
    pub seq: u8,
    pub flags: Flags,
    pub session_id: u32,
    pub body: &'a mut [u8],
}

impl<'a> Packet<'a> {
    pub const HEADER_LENGTH: usize = 12;

    pub fn decode(buf: &'a mut [u8], secret_key: &[u8]) -> Result<Option<Packet<'a>>, PacketError> {
        if buf.len() < Packet::HEADER_LENGTH {
            return Ok(None);
        }

        let mut hdr = &buf[..Packet::HEADER_LENGTH];
        let version = Version::decode(hdr.get_u8());
        if version.major != Version::MAJOR_VER {
            return Err(PacketError::InvalidValue(version.major, "major version"));
        }
        if version.minor != Version::MINOR_VER_DEFAULT
            && version.minor != Version::MINOR_VER_ONE
        {
            return Err(PacketError::InvalidValue(version.minor, "minor version"));
        }

        let ptype_byte = hdr.get_u8();
        let ptype = PacketType::try_from(ptype_byte)
            .map_err(|_| PacketError::InvalidValue(ptype_byte, "packet type"))?;
        let seq = hdr.get_u8();
        let flags = Flags::from_bits_truncate(hdr.get_u8());
        let session_id = hdr.get_u32();
        let length = hdr.get_u32();

        let total_len = Packet::HEADER_LENGTH + length as usize;
        if buf.len() < total_len {
            return Ok(None);
        }

        let body = &mut buf[Packet::HEADER_LENGTH..total_len];

        if !flags.contains(Flags::UNENCRYPTED) {
            obfuscate(body, session_id, secret_key, version.encode(), seq);
        }

        Ok(Some(Packet {
            version,
            ptype,
            seq,
            flags,
            session_id,
            body,
        }))
    }

    /// Total packet length (header + body).
    pub fn len(&self) -> usize {
        Self::HEADER_LENGTH + self.body.len()
    }

    /// Encode header into buf with the given body length.
    pub fn encode_header(&self, buf: &mut [u8], body_len: u32) {
        let mut buf = buf;
        buf.put_u8(self.version.encode());
        buf.put_u8(self.ptype as u8);
        buf.put_u8(self.seq);
        buf.put_u8(self.flags.bits());
        buf.put_u32(self.session_id);
        buf.put_u32(body_len);
    }
}

// Authentication types

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum AuthenAction {
    Login = 0x01,
    ChPass = 0x02,
    SendAuth = 0x04,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum AuthenType {
    Ascii = 0x01,
    Pap = 0x02,
    Chap = 0x03,
    MsChap = 0x05,
    MsChapV2 = 0x06,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum AuthenService {
    None = 0x00,
    Login = 0x01,
    Enable = 0x02,
    Ppp = 0x03,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum AuthenStatus {
    Pass = 0x01,
    Fail = 0x02,
    GetData = 0x03,
    GetUser = 0x04,
    GetPass = 0x05,
    Restart = 0x06,
    Error = 0x07,
    Follow = 0x21,
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AuthenReplyFlags: u8 {
        const NOECHO = 0x01;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AuthenContinueFlags: u8 {
        const ABORT = 0x01;
    }
}

#[derive(Debug)]
pub struct AuthenStart<'a> {
    pub action: AuthenAction,
    pub priv_lvl: u8,
    pub authen_type: AuthenType,
    pub authen_service: AuthenService,
    pub user: &'a [u8],
    pub port: &'a [u8],
    pub rem_addr: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> AuthenStart<'a> {
    const FIXED_LEN: usize = 8;

    pub fn decode(buf: &'a [u8]) -> Result<Self, PacketError> {
        if buf.len() < Self::FIXED_LEN {
            return Err(PacketError::Truncated("authen start header"));
        }

        let mut hdr = &buf[..Self::FIXED_LEN];
        let action_byte = hdr.get_u8();
        let action = AuthenAction::try_from(action_byte)
            .map_err(|_| PacketError::InvalidValue(action_byte, "authen action"))?;
        let priv_lvl = hdr.get_u8();
        let authen_type_byte = hdr.get_u8();
        let authen_type = AuthenType::try_from(authen_type_byte)
            .map_err(|_| PacketError::InvalidValue(authen_type_byte, "authen type"))?;
        let authen_service_byte = hdr.get_u8();
        let authen_service = AuthenService::try_from(authen_service_byte)
            .map_err(|_| PacketError::InvalidValue(authen_service_byte, "authen service"))?;
        let user_len = hdr.get_u8() as usize;
        let port_len = hdr.get_u8() as usize;
        let rem_addr_len = hdr.get_u8() as usize;
        let data_len = hdr.get_u8() as usize;

        let expected_len = Self::FIXED_LEN + user_len + port_len + rem_addr_len + data_len;
        if buf.len() != expected_len {
            return Err(PacketError::BadBodyLen {
                expected: expected_len,
                actual: buf.len(),
            });
        }

        let mut offset = Self::FIXED_LEN;
        let user = &buf[offset..offset + user_len];
        offset += user_len;
        let port = &buf[offset..offset + port_len];
        offset += port_len;
        let rem_addr = &buf[offset..offset + rem_addr_len];
        offset += rem_addr_len;
        let data = &buf[offset..offset + data_len];

        Ok(Self {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        })
    }

}

impl PacketBody for AuthenStart<'_> {
    fn len(&self) -> usize {
        Self::FIXED_LEN + self.user.len() + self.port.len() + self.rem_addr.len() + self.data.len()
    }

    fn encode(&self, buf: &mut [u8]) {
        let mut buf = buf;
        buf.put_u8(self.action as u8);
        buf.put_u8(self.priv_lvl);
        buf.put_u8(self.authen_type as u8);
        buf.put_u8(self.authen_service as u8);
        buf.put_u8(self.user.len() as u8);
        buf.put_u8(self.port.len() as u8);
        buf.put_u8(self.rem_addr.len() as u8);
        buf.put_u8(self.data.len() as u8);
        buf.put_slice(self.user);
        buf.put_slice(self.port);
        buf.put_slice(self.rem_addr);
        buf.put_slice(self.data);
    }
}

#[derive(Debug)]
pub struct AuthenReply<'a> {
    pub status: AuthenStatus,
    pub flags: AuthenReplyFlags,
    pub server_msg: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> AuthenReply<'a> {
    const FIXED_LEN: usize = 6;

    pub fn decode(buf: &'a [u8]) -> Result<Self, PacketError> {
        if buf.len() < Self::FIXED_LEN {
            return Err(PacketError::Truncated("authen reply header"));
        }

        let mut hdr = &buf[..Self::FIXED_LEN];
        let status_byte = hdr.get_u8();
        let status = AuthenStatus::try_from(status_byte)
            .map_err(|_| PacketError::InvalidValue(status_byte, "authen status"))?;
        let flags = AuthenReplyFlags::from_bits_truncate(hdr.get_u8());
        let server_msg_len = hdr.get_u16() as usize;
        let data_len = hdr.get_u16() as usize;

        let expected_len = Self::FIXED_LEN + server_msg_len + data_len;
        if buf.len() != expected_len {
            return Err(PacketError::BadBodyLen {
                expected: expected_len,
                actual: buf.len(),
            });
        }

        let server_msg = &buf[Self::FIXED_LEN..Self::FIXED_LEN + server_msg_len];
        let data = &buf[Self::FIXED_LEN + server_msg_len..];

        Ok(Self {
            status,
            flags,
            server_msg,
            data,
        })
    }
}

impl PacketBody for AuthenReply<'_> {
    fn len(&self) -> usize {
        6 + self.server_msg.len() + self.data.len()
    }

    fn encode(&self, buf: &mut [u8]) {
        let mut buf = buf;
        buf.put_u8(self.status as u8);
        buf.put_u8(self.flags.bits());
        buf.put_u16(self.server_msg.len() as u16);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(self.server_msg);
        buf.put_slice(self.data);
    }
}

#[derive(Debug)]
pub struct AuthenContinue<'a> {
    pub user_msg: &'a [u8],
    pub data: &'a [u8],
    pub flags: AuthenContinueFlags,
}

impl<'a> AuthenContinue<'a> {
    const FIXED_LEN: usize = 5;

    pub fn decode(buf: &'a [u8]) -> Result<Self, PacketError> {
        if buf.len() < Self::FIXED_LEN {
            return Err(PacketError::Truncated("authen continue header"));
        }

        let mut hdr = &buf[..Self::FIXED_LEN];
        let user_msg_len = hdr.get_u16() as usize;
        let data_len = hdr.get_u16() as usize;
        let flags = AuthenContinueFlags::from_bits_truncate(hdr.get_u8());

        let expected_len = Self::FIXED_LEN + user_msg_len + data_len;
        if buf.len() != expected_len {
            return Err(PacketError::BadBodyLen {
                expected: expected_len,
                actual: buf.len(),
            });
        }

        let user_msg = &buf[Self::FIXED_LEN..Self::FIXED_LEN + user_msg_len];
        let data = &buf[Self::FIXED_LEN + user_msg_len..];

        Ok(Self {
            user_msg,
            data,
            flags,
        })
    }
}

impl PacketBody for AuthenContinue<'_> {
    fn len(&self) -> usize {
        5 + self.user_msg.len() + self.data.len()
    }

    fn encode(&self, buf: &mut [u8]) {
        let mut buf = buf;
        buf.put_u16(self.user_msg.len() as u16);
        buf.put_u16(self.data.len() as u16);
        buf.put_u8(self.flags.bits());
        buf.put_slice(self.user_msg);
        buf.put_slice(self.data);
    }
}

/// obfuscate implements the "encryption" for TACACS as defined in RFC8907
/// section 4.5.  It will mutate the bytes in place and is bidirectional.
pub fn obfuscate(buf: &mut [u8], session_id: u32, secret_key: &[u8], version: u8, seq: u8) {
    let mut prev_hash: Option<[u8; 16]> = None;

    for chunk in buf.chunks_mut(16) {
        let mut ctx = md5::Context::new();
        ctx.consume(session_id.to_be_bytes());
        ctx.consume(secret_key);
        ctx.consume([version, seq]);

        if let Some(h) = &prev_hash {
            ctx.consume(h);
        }

        let hash: [u8; 16] = *ctx.finalize();
        prev_hash = Some(hash);

        for (v, h) in chunk.iter_mut().zip(hash.iter()) {
            *v ^= h;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_obfuscate() {
        let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur in facilisis metus, in tempor sem.";
        let mut buf = input.to_vec();
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

        obfuscate(&mut buf, 1581998937, b"test", 0xc << 4, 1);
        assert_eq!(buf, encrypted);

        // "decrypting" is the same operation.
        obfuscate(&mut buf, 1581998937, b"test", 0xc << 4, 1);
        assert_eq!(buf, input);
    }

    #[test]
    fn test_version_encode_decode() {
        let ver = Version {
            major: 0x0C,
            minor: 0x01,
        };
        let encoded = ver.encode();
        assert_eq!(encoded, 0xC1);

        let decoded = Version::decode(encoded);
        assert_eq!(decoded.major, 0x0C);
        assert_eq!(decoded.minor, 0x01);
    }

    #[test]
    fn test_packet_header_encode_decode() {
        let pkt = Packet {
            version: Version {
                major: Version::MAJOR_VER,
                minor: Version::MINOR_VER_DEFAULT,
            },
            ptype: PacketType::Authen,
            seq: 1,
            flags: Flags::SINGLE_CONNECT,
            session_id: 0x12345678,
            body: &mut [],
        };

        let mut buf = [0u8; Packet::HEADER_LENGTH];
        pkt.encode_header(&mut buf, 100);

        assert_eq!(buf[0], 0xC0); // version
        assert_eq!(buf[1], 0x01); // type (Authen)
        assert_eq!(buf[2], 0x01); // seq
        assert_eq!(buf[3], 0x04); // flags (SINGLE_CONNECT)
        assert_eq!(&buf[4..8], &[0x12, 0x34, 0x56, 0x78]); // session_id
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x00, 0x64]); // length (100)
    }

    #[test]
    fn test_packet_decode() {
        let mut buf = [
            0xC0, // version
            0x01, // type (Authen)
            0x01, // seq
            0x01, // flags (UNENCRYPTED)
            0x12, 0x34, 0x56, 0x78, // session_id
            0x00, 0x00, 0x00, 0x04, // length
            0xDE, 0xAD, 0xBE, 0xEF, // body
        ];

        let pkt = Packet::decode(&mut buf, b"secret").unwrap().unwrap();
        assert_eq!(pkt.version.major, 0x0C);
        assert_eq!(pkt.version.minor, 0x00);
        assert_eq!(pkt.seq, 1);
        assert!(pkt.flags.contains(Flags::UNENCRYPTED));
        assert_eq!(pkt.session_id, 0x12345678);
        assert_eq!(pkt.body, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_authen_start_encode_decode() {
        let start = AuthenStart {
            action: AuthenAction::Login,
            priv_lvl: 15,
            authen_type: AuthenType::Ascii,
            authen_service: AuthenService::Login,
            user: b"admin",
            port: b"tty0",
            rem_addr: b"192.168.1.1",
            data: b"",
        };

        let mut buf = vec![0u8; 256];
        start.encode(&mut buf);

        let decoded = AuthenStart::decode(&buf[..start.len()]).unwrap();
        assert_eq!(decoded.action as u8, AuthenAction::Login as u8);
        assert_eq!(decoded.priv_lvl, 15);
        assert_eq!(decoded.authen_type as u8, AuthenType::Ascii as u8);
        assert_eq!(decoded.authen_service as u8, AuthenService::Login as u8);
        assert_eq!(decoded.user, b"admin");
        assert_eq!(decoded.port, b"tty0");
        assert_eq!(decoded.rem_addr, b"192.168.1.1");
        assert_eq!(decoded.data, b"");
    }

    #[test]
    fn test_authen_start_len() {
        let start = AuthenStart {
            action: AuthenAction::Login,
            priv_lvl: 0,
            authen_type: AuthenType::Ascii,
            authen_service: AuthenService::Login,
            user: b"admin",
            port: b"tty0",
            rem_addr: b"192.168.1.1",
            data: b"secret",
        };
        // 8 fixed + 5 (user) + 4 (port) + 11 (rem_addr) + 6 (data)
        assert_eq!(start.len(), 8 + 5 + 4 + 11 + 6);
    }

    #[test]
    fn test_authen_reply_encode_decode() {
        let reply = AuthenReply {
            status: AuthenStatus::GetPass,
            flags: AuthenReplyFlags::NOECHO,
            server_msg: b"Password: ",
            data: b"",
        };

        let mut buf = vec![0u8; reply.len()];
        reply.encode(&mut buf);

        let decoded = AuthenReply::decode(&buf).unwrap();
        assert_eq!(decoded.status as u8, AuthenStatus::GetPass as u8);
        assert!(decoded.flags.contains(AuthenReplyFlags::NOECHO));
        assert_eq!(decoded.server_msg, b"Password: ");
        assert_eq!(decoded.data, b"");
    }

    #[test]
    fn test_authen_reply_len() {
        let reply = AuthenReply {
            status: AuthenStatus::Pass,
            flags: AuthenReplyFlags::empty(),
            server_msg: b"Welcome",
            data: b"extra",
        };
        // 6 fixed + 7 (server_msg) + 5 (data)
        assert_eq!(reply.len(), 6 + 7 + 5);
    }

    #[test]
    fn test_authen_continue_encode_decode() {
        let cont = AuthenContinue {
            user_msg: b"mypassword",
            data: b"",
            flags: AuthenContinueFlags::empty(),
        };

        let mut buf = vec![0u8; cont.len()];
        cont.encode(&mut buf);

        let decoded = AuthenContinue::decode(&buf).unwrap();
        assert_eq!(decoded.user_msg, b"mypassword");
        assert_eq!(decoded.data, b"");
        assert!(!decoded.flags.contains(AuthenContinueFlags::ABORT));
    }

    #[test]
    fn test_authen_continue_len() {
        let cont = AuthenContinue {
            user_msg: b"password",
            data: b"extra",
            flags: AuthenContinueFlags::ABORT,
        };
        // 5 fixed + 8 (user_msg) + 5 (data)
        assert_eq!(cont.len(), 5 + 8 + 5);
    }

    #[test]
    fn test_authen_start_bad_body_len() {
        // Valid header but body is too short
        let buf = [
            0x01, // action (Login)
            0x0F, // priv_lvl
            0x01, // authen_type (Ascii)
            0x01, // authen_service (Login)
            0x05, // user_len (5)
            0x04, // port_len (4)
            0x00, // rem_addr_len (0)
            0x00, // data_len (0)
            b'a', b'd', b'm', b'i', b'n', // user (5 bytes)
            // missing port bytes
        ];

        let err = AuthenStart::decode(&buf).unwrap_err();
        assert!(matches!(err, PacketError::BadBodyLen { .. }));
    }

    #[test]
    fn test_authen_reply_bad_body_len() {
        let buf = [
            0x01, // status (Pass)
            0x00, // flags
            0x00, 0x05, // server_msg_len (5)
            0x00, 0x00, // data_len (0)
            b'h', b'e', b'l', b'l', // only 4 bytes, expected 5
        ];

        let err = AuthenReply::decode(&buf).unwrap_err();
        assert!(matches!(err, PacketError::BadBodyLen { .. }));
    }

    #[test]
    fn test_authen_continue_bad_body_len() {
        let buf = [
            0x00, 0x03, // user_msg_len (3)
            0x00, 0x00, // data_len (0)
            0x00, // flags
            b'a', b'b', // only 2 bytes, expected 3
        ];

        let err = AuthenContinue::decode(&buf).unwrap_err();
        assert!(matches!(err, PacketError::BadBodyLen { .. }));
    }
}
