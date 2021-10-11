use crate::{Error, COOKIE};
use bitfield::bitfield;
use std::convert::TryFrom;

#[allow(clippy::len_without_is_empty)]
bitfield! {
    pub struct MessageHead(u32);

    u8;
    pub z, _: 31, 30;

    u16;
    pub typ, set_typ: 29, 16;

    #[allow(clippy::len_without_is_empty)]
    pub len, set_len: 15, 0;
}

bitfield! {
    pub struct MessageId(u128);

    u32;
    pub cookie, set_cookie: 127,  96;

    u128;
    pub tsx_id, set_tsx_id: 95, 0;
}

impl MessageId {
    pub(crate) fn new() -> Self {
        let mut new = Self(0);
        new.set_cookie(COOKIE);
        new
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    const MASK: u16 = 0x110;

    const REQUEST: u16 = 0x000;
    const INDICATION: u16 = 0x010;
    const SUCCESS: u16 = 0x100;
    const ERROR: u16 = 0x110;

    pub fn set(&self, typ: &mut u16) {
        *typ &= Method::MASK;

        match self {
            Class::Request => *typ |= Self::REQUEST,
            Class::Indication => *typ |= Self::INDICATION,
            Class::Success => *typ |= Self::SUCCESS,
            Class::Error => *typ |= Self::ERROR,
        }
    }
}

impl TryFrom<u16> for Class {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value & Self::MASK {
            Self::REQUEST => Ok(Self::Request),
            Self::INDICATION => Ok(Self::Indication),
            Self::SUCCESS => Ok(Self::Success),
            Self::ERROR => Ok(Self::Error),
            _ => Err(Error::InvalidData("unknown class")),
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Method {
    Binding,
}

impl Method {
    const MASK: u16 = 0x3EEF;

    const BINDING: u16 = 0x1;

    pub fn set(&self, typ: &mut u16) {
        *typ &= Class::MASK;

        match self {
            Method::Binding => *typ |= Self::BINDING,
        }
    }
}

impl TryFrom<u16> for Method {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value & Self::MASK {
            Self::BINDING => Ok(Self::Binding),
            _ => Err(Error::InvalidData("unknown method")),
        }
    }
}
