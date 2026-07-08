use proxy_core::{Protocol, Server};

mod xray {}

pub mod vless;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing protocol")]
    MissingProtocol,
    #[error("unknown protocol")]
    UnknownProtocol,
    #[error("vless parse error")]
    Vless(#[source] vless::Error),
}

pub fn parse_url(s: &str) -> Result<(Server<String>, Protocol), Error> {
    match s.split_once("://").ok_or(Error::MissingProtocol)?.0 {
        "vless" => vless::parse_vless(s).map_err(Error::Vless),
        _ => Err(Error::UnknownProtocol),
    }
}
