use std::{
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "ty", content = "addr")]
pub enum ServerAddr<S> {
    Ip(IpAddr),
    Domain(S),
}

pub mod vless;
pub mod xray;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpingResult {
    pub peer_addr: SocketAddr,
    pub duration: std::time::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ty", content = "config")]
pub enum Protocol {
    #[serde(rename = "vless")]
    Vless(vless::Vless),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server<S> {
    pub name: Option<S>,
    pub addr: ServerAddr<S>,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectKind<S> {
    ConnectTest {
        success: bool,
    },
    Tcping {
        success: bool,
        server_addr: Option<S>,
        result: Option<TcpingResult>,
    },
    Connect,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionServer<U> {
    pub url: U,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo<SS, SA> {
    pub id: uuid::Uuid,
    pub servers: SS,
    pub timestamp: SystemTime,
    pub kind: ConnectKind<SA>,
}
