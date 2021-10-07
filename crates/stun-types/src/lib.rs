pub mod attributes;
mod msg;

pub use msg::{AttrInsertQueue, Class, MessageBuilder, Method, ParsedAttr, ParsedMessage};

type NE = byteorder::NetworkEndian;

const COOKIE: u32 = 0x2112A442;

fn padding_u16(n: u16) -> u16 {
    match n % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}

fn padding_usize(n: usize) -> usize {
    match n % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}

pub fn transaction_id() -> u128 {
    rand::random::<u128>() & !((u32::MAX as u128) << 96)
}
