use super::NE;
use crate::{padding_usize, MessageBuilder, ParsedAttr, ParsedMessage};
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut, Bytes};
use bytesstr::BytesStr;
use hmac::digest::Digest;
use sha2::Sha256;
use std::convert::TryFrom;
use std::io;
use std::io::Cursor;
use std::num::TryFromIntError;
use std::str::Utf8Error;

mod addr;
mod error_code;
mod fingerprint;
mod integrity;
mod password_algs;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input data, {0}")]
    InvalidData(&'static str),
    #[error("failed to convert integer")]
    TryFromInt(#[from] TryFromIntError),
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::InvalidData("failed to read from buffer")
    }
}

pub trait Attribute {
    type Context;
    const TYPE: u16;

    fn decode(ctx: Self::Context, msg: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error>
    where
        Self: Sized;

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error>;

    fn encode_len(&self) -> Result<u16, Error>;
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.3)
pub struct Username(pub BytesStr);

impl Attribute for Username {
    type Context = ();
    const TYPE: u16 = 0x0006;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        Ok(Self(BytesStr::from_utf8_bytes(attr.value.clone())?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(self.0.as_ref());
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.4)
pub struct UserHash(pub [u8; 32]);

impl UserHash {
    pub fn new(username: &str, realm: &str) -> Self {
        let input = format!("{}:{}", username, realm);
        let output = Sha256::digest(input.as_bytes());

        Self(output.into())
    }
}

impl Attribute for UserHash {
    type Context = ();
    const TYPE: u16 = 0x001E;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        if attr.value.len() != 32 {
            return Err(Error::InvalidData("user hash buf must be 32 bytes"));
        }

        Ok(Self(<[u8; 32]>::try_from(attr.value.as_ref()).unwrap()))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(&self.0);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(32)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.9)
pub struct Realm(pub BytesStr);

impl Attribute for Realm {
    type Context = ();
    const TYPE: u16 = 0x0014;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        Ok(Self(BytesStr::from_utf8_bytes(attr.value.clone())?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(self.0.as_ref());
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.10)
pub struct Nonce(pub Bytes);

impl Attribute for Nonce {
    type Context = ();
    const TYPE: u16 = 0x0015;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.value.clone()))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(&self.0);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.12)
pub struct PasswordAlgorithm {
    algorithm: u16,
    params: Bytes,
}

impl Attribute for PasswordAlgorithm {
    type Context = ();
    const TYPE: u16 = 0x001D;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        let mut cursor = Cursor::new(&attr.value);

        let alg = cursor.read_u16::<NE>()?;
        let len = usize::from(cursor.read_u16::<NE>()?);

        let pos = usize::try_from(cursor.position())?;

        if attr.value.len() < pos + len {
            return Err(Error::InvalidData("invalid algorithm len"));
        }

        let params = attr.value.slice(pos..pos + len);

        Ok(Self {
            algorithm: alg,
            params,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let padding = padding_usize(self.params.len());

        builder.buffer().put_u16(self.algorithm);
        builder.buffer().put_u16(u16::try_from(self.params.len())?);
        builder.buffer().extend_from_slice(&self.params);
        builder.buffer().extend((0..padding).map(|_| 0));

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(
            4 + self.params.len() + padding_usize(self.params.len()),
        )?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.13)
pub struct UnknownAttributes {
    attributes: Vec<u16>,
}

impl Attribute for UnknownAttributes {
    type Context = ();
    const TYPE: u16 = 0x000A;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        let mut cursor = Cursor::new(&attr.value);

        let mut attributes = vec![];

        while cursor.has_remaining() {
            attributes.push(cursor.read_u16::<NE>()?);
        }

        Ok(Self { attributes })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        for &attr in &self.attributes {
            builder.buffer().put_u16(attr);
        }

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.attributes.len() * 2)?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.14)
pub struct Software(pub BytesStr);

impl Attribute for Software {
    type Context = ();
    const TYPE: u16 = 0x8022;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        Ok(Self(BytesStr::from_utf8_bytes(attr.value.clone())?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(self.0.as_ref());
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.15)
pub struct AlternateDomain(pub Bytes);

impl Attribute for AlternateDomain {
    type Context = ();
    const TYPE: u16 = 0x8003;

    fn decode(_: Self::Context, _: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.value.clone()))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(&self.0);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}
