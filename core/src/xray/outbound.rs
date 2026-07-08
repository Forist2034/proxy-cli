use std::borrow::Cow;

use serde::Serialize;

#[derive(Serialize)]
pub struct VLess<'a> {
    pub address: super::RemoteAddr<'a>,
    pub port: u16,
    pub id: &'a str,
    pub encryption: Option<Cow<'a, str>>,
    pub flow: Option<Cow<'a, str>>,
}
