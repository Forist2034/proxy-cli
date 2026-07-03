use serde::{Deserialize, Serialize};

macro_rules! mk_enum {
    (enum $n:ident {
        $($c:ident = $v:literal,)*
    }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $n {
            $(#[serde(rename = $v)] $c,)*
        }
        impl $n {
            pub const fn to_str(self) -> &'static str {
                match self {
                    $(Self::$c => $v,)*
                }
            }
            pub fn from_str(s: &str) -> Option<Self> {
                match s {
                    $($v => Some(Self::$c),)*
                    _ => None
                }
            }
        }
    };
}

mk_enum!(
    enum Type {
        Tcp = "tcp",
        Kcp = "kcp",
        Ws = "ws",
        Http = "http",
        Quic = "quic",
        GRpc = "grpc",
    }
);

mk_enum!(
    enum Encryption {
        None = "none",
        Auto = "auto",
        Aes128Gcm = "aes-128-gcm",
        Chacha20Poly1305 = "chacha20-poly1305",
    }
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http {
    pub host: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocket {
    pub host: Option<String>,
    pub path: String,
}

mk_enum!(
    enum HeaderType {
        None = "none",
        Srtp = "srtp",
        Utp = "utp",
        WechatVideo = "wechat-video",
        DTls = "dtls",
        Wireguard = "wireguard",
    }
);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MKcp {
    pub header_type: HeaderType,
    pub seed: Option<String>,
}

mk_enum!(
    enum QuicSecurityType {
        None = "none",
        Aes128Gcm = "aes-128-gcm",
        Chacha20Poly1305 = "chacha20-poly1305",
    }
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ty", content = "config")]
pub enum QuicSecurity {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm(String),
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305(String),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quic {
    pub header_type: HeaderType,
    pub security: QuicSecurity,
}

mk_enum!(
    enum GRpcMode {
        Gun = "gun",
        Multi = "multi",
        Guna = "guna",
    }
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GRpc {
    pub service_name: Option<String>,
    pub mode: GRpcMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ty", content = "config")]
pub enum Trans {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "kcp")]
    Kcp(MKcp),
    #[serde(rename = "ws")]
    Ws(WebSocket),
    #[serde(rename = "http")]
    Http(Http),
    #[serde(rename = "quic")]
    Quic(Quic),
    #[serde(rename = "grpc")]
    GRpc(GRpc),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls {
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
}

mk_enum!(
    enum SecurityType {
        None = "none",
        Tls = "tls",
        Xtls = "xtls",
    }
);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ty", content = "config")]
pub enum Security {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "tls")]
    Tls(Tls),
    #[serde(rename = "xtls")]
    XTls { tls: Tls, flow: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vless {
    pub uuid: uuid::Uuid,
    pub transport: Trans,
    pub security: Security,
}
