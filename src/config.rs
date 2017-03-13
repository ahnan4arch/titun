// Copyright 2017 Sopium

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

extern crate serde_yaml;
extern crate rustc_serialize;

use self::rustc_serialize::base64::FromBase64;
use self::serde_yaml as yaml;
use error::Result;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use wireguard::{PeerInfo, WgInfo};
use wireguard::re_exports::U8Array;

#[derive(Serialize, Deserialize)]
struct PeerConfigSerde {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keep_alive: Option<u16>,
}

#[derive(Serialize, Deserialize)]
struct ConfigSerde {
    pub dev_name: String,
    pub listen_port: Option<u16>,
    pub psk: Option<String>,
    pub key: String,
    pub peers: Vec<PeerConfigSerde>,

    pub on_up: Option<String>,
    pub on_down: Option<String>,
}

pub struct Config {
    pub dev_name: String,
    pub listen_port: Option<u16>,
    pub info: WgInfo,
    pub peers: Vec<PeerInfo>,
    pub on_up: Option<String>,
    pub on_down: Option<String>,
}

fn to_socket_addr<S>(s: S) -> Result<SocketAddr>
    where S: ToSocketAddrs
{
    for a in s.to_socket_addrs()? {
        return Ok(a);
    }
    Err(From::from("cannot resolve host"))
}

fn base64_to_arr<A>(x: String) -> Result<A>
    where A: U8Array
{
    let x = x.from_base64()?;
    if x.len() == A::len() {
        Ok(A::from_slice(&x))
    } else {
        Err(From::from("not 32 bytes"))
    }
}

fn parse_cidr<S>(s: S) -> Result<(IpAddr, u32)>
    where S: AsRef<str>
{
    let s = s.as_ref();

    let ss = s.split('/').collect::<Vec<_>>();

    if ss.len() == 2 {
        let a = ss[0].parse()?;
        let p = ss[1].parse()?;
        Ok((a, p))
    } else if ss.len() == 1 {
        let a = ss[0].parse()?;
        let prefix = match a {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Ok((a, prefix))
    } else {
        Err(From::from("failed to parse allowed IPs."))
    }
}

fn lift_err<T>(x: Option<Result<T>>) -> Result<Option<T>> {
    match x {
        Some(Ok(t)) => Ok(Some(t)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

// Will only get the first error.
fn lift_err_vec<T>(x: Vec<Result<T>>) -> Result<Vec<T>> {
    let mut z = Vec::new();
    for y in x {
        z.push(y?);
    }
    Ok(z)
}

impl Config {
    pub fn parse(s: &str) -> Result<Config> {
        let c: ConfigSerde = yaml::from_str(s)?;

        let psk = lift_err(c.psk.map(base64_to_arr))?;

        let key = base64_to_arr(c.key)?;

        let peers = lift_err_vec(c.peers
            .into_iter()
            .map(|p| {
                let pk = base64_to_arr(p.public_key)?;
                let endpoint = lift_err(p.endpoint.map(to_socket_addr))?;
                let allowed_ips = lift_err_vec(p.allowed_ips
                    .into_iter()
                    .map(parse_cidr)
                    .collect())?;
                Ok(PeerInfo {
                    peer_pubkey: pk,
                    endpoint: endpoint,
                    allowed_ips: allowed_ips,
                    keep_alive_interval: p.keep_alive,
                })
            })
            .collect())?;

        Ok(Config {
            dev_name: c.dev_name,
            listen_port: c.listen_port,
            info: WgInfo::new(psk, key),
            peers: peers,
            on_up: c.on_up,
            on_down: c.on_down,
        })
    }
}
