use std::{borrow::Cow, net::IpAddr};

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum RemoteAddr<'a> {
    Ip(IpAddr),
    Domain(&'a str),
}

pub mod outbound;
pub mod transport;

#[derive(serde::Serialize)]
pub enum ProtocolType {
    #[serde(rename = "vless")]
    VLess,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum OutboundSettings<'a> {
    VLess(outbound::VLess<'a>),
}

#[derive(serde::Serialize)]
pub struct OutboundConfig<'a, S> {
    pub name: Option<Cow<'a, str>>,
    pub protocol: ProtocolType,
    pub stream: transport::StreamSettings<'a>,
    pub settings: S,
}
