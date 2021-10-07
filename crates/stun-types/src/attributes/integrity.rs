use super::{Attribute, Error};
use crate::{MessageBuilder, ParsedAttr, ParsedMessage};
use hmac::digest::generic_array::ArrayLength;
use hmac::digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::Sha256;
use std::convert::TryFrom;

fn message_integrity_decode<D>(
    mut hmac: Hmac<D>,
    msg: &ParsedMessage,
    attr: &ParsedAttr,
) -> Result<(), Error>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    hmac.update(&msg.buffer()[..attr.attr_idx]);

    let result = hmac.finalize().into_bytes();

    if result.as_slice() != attr.value {
        return Err(Error::InvalidData("failed to verify message integrity"));
    }

    Ok(())
}

fn message_integrity_encode<D>(mut hmac: Hmac<D>, builder: &mut MessageBuilder)
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
{
    let data = builder.buffer();
    let data = &data[..data.len() - 4];

    hmac.update(data);

    let raw = hmac.finalize().into_bytes();

    builder.buffer().extend_from_slice(&raw);
}

pub fn new_hmac_sha1(password: &str) -> Hmac<Sha1> {
    Hmac::new_from_slice(&md5::compute(password).0).expect("md5 will always yield the right length")
}

pub fn new_hmac_sha256(password: &str) -> Hmac<Sha256> {
    Hmac::new_from_slice(&md5::compute(password).0).expect("md5 will always yield the right length")
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.5)
pub struct MessageIntegrity;

impl Attribute for MessageIntegrity {
    type Context = Hmac<Sha1>;
    const TYPE: u16 = 0x0008;

    fn decode(ctx: Self::Context, msg: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        message_integrity_decode(ctx, msg, attr)?;

        Ok(Self)
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        message_integrity_encode(ctx, builder);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(Sha1::output_size())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.6)
pub struct MessageIntegritySha256;

impl Attribute for MessageIntegritySha256 {
    type Context = Hmac<Sha256>;
    const TYPE: u16 = 0x001C;

    fn decode(ctx: Self::Context, msg: &ParsedMessage, attr: &ParsedAttr) -> Result<Self, Error> {
        message_integrity_decode(ctx, msg, attr)?;

        Ok(Self)
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        message_integrity_encode(ctx, builder);
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(Sha256::output_size())?)
    }
}
