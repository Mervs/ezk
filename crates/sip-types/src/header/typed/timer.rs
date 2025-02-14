use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx};
use crate::uri::params::{Params, CPS};
use crate::Name;
use anyhow::Result;
use internal::ws;
use nom::character::complete::alphanumeric1;
use nom::combinator::map_res;
use nom::IResult;
use std::fmt;
use std::str::FromStr;

decl_from_str_header!(
    /// `Min-SE` header
    MinSe,
    u32,
    Single,
    Name::MIN_SE
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresher {
    Unspecified,
    Uas,
    Uac,
}

/// Session-Expires header
#[derive(Debug, Clone, Copy)]
pub struct SessionExpires {
    pub delta_secs: u32,
    pub refresher: Refresher,
}

impl SessionExpires {
    pub fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map_res(
                ws((
                    map_res(alphanumeric1, FromStr::from_str),
                    Params::<CPS>::parse(ctx),
                )),
                |(delta_secs, mut params)| -> Result<Self> {
                    let refresher = if let Some(param) = params.take("refresher") {
                        match param.as_str() {
                            "uas" => Refresher::Uas,
                            "uac" => Refresher::Uac,
                            _ => Refresher::Unspecified,
                        }
                    } else {
                        Refresher::Unspecified
                    };

                    Ok(Self {
                        delta_secs,
                        refresher,
                    })
                },
            )(i)
        }
    }
}

impl Print for SessionExpires {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}", self.delta_secs)?;

        match self.refresher {
            Refresher::Unspecified => {}
            Refresher::Uas => write!(f, ";refresher=uas")?,
            Refresher::Uac => write!(f, ";refresher=uac")?,
        }

        Ok(())
    }
}

__impl_header!(SessionExpires, Single, Name::SESSION_EXPIRES);

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;

    #[test]
    fn min_se() {
        let input = BytesStr::from_static("160");

        let (rem, min_se) = MinSe::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(min_se.0, 160);
    }

    #[test]
    fn session_expires() {
        let input = BytesStr::from_static("1000");

        let (rem, se) = SessionExpires::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Unspecified);
    }

    #[test]
    fn session_expires_refresher_uac() {
        let input = BytesStr::from_static("1000;refresher=uac");

        let (rem, se) = SessionExpires::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Uac);
    }

    #[test]
    fn session_expires_refresher_uas() {
        let input = BytesStr::from_static("1000;refresher=uas");

        let (rem, se) = SessionExpires::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Uas);
    }
}
