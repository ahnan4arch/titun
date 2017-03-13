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

extern crate nix;

use self::nix::libc::{in6_addr, in_addr, sockaddr, sockaddr_in, sockaddr_in6, timeval};
use std;
// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const IFNAMSIZ: usize = 16;
const WG_KEY_LEN: usize = 32;

#[repr(C)]
pub struct WgDevice {
    pub interface: [u8; IFNAMSIZ], // get
    pub flags: u32, // set
    pub public_key: [u8; WG_KEY_LEN], // get
    pub private_key: [u8; WG_KEY_LEN],
    pub preshared_key: [u8; WG_KEY_LEN],
    pub fwmark: u32,
    pub port: u16,
    pub num_peers: u16,
}

#[repr(C)]
pub struct WgIpMask {
    pub family: i32,
    pub addr: Addr,
    pub cidr: u8,
}

#[repr(C)]
pub union Addr {
    pub ip4: in_addr,
    pub ip6: in6_addr,
}

#[repr(C)]
pub struct WgPeer {
    pub public_key: [u8; WG_KEY_LEN],
    pub flags: u32, // set
    pub endpoint: WgEndpoint,
    pub last_handshake_time: timeval, // get
    pub rx_bytes: u64, // get
    pub tx_bytes: u64, // get
    pub persistent_keepalive_interval: u16,
    pub num_ipmasks: u16,
}

#[repr(C)]
pub union WgEndpoint {
    pub addr: sockaddr,
    pub addr4: sockaddr_in,
    pub addr6: sockaddr_in6,
}

/// The peer with this public key should be removed.
pub const WGPEER_REMOVE_ME: u32 = (1 << 0);
/// Remove allowed IPs before adding.
pub const WGPEER_REPLACE_IPMASKS: u32 = (1 << 1);

/// Remove peers before adding.
pub const WGDEVICE_REPLACE_PEERS: u32 = (1 << 0);
pub const WGDEVICE_REMOVE_PRIVATE_KEY: u32 = (1 << 1);
pub const WGDEVICE_REMOVE_PRESHARED_KEY: u32 = (1 << 2);
pub const WGDEVICE_REMOVE_FWMARK: u32 = (1 << 3);

// To and from bytes.

macro_rules! marshal {
($t:tt) => {

impl AsRef<[u8]> for $t {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<$t>())
        }
    }
}

impl AsMut<[u8]> for $t {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self as *mut _ as *mut u8, std::mem::size_of::<$t>())
        }
    }
}

impl $t {
    pub fn read_from<R>(mut r: R) -> Result<$t, std::io::Error>
        where R: std::io::Read
    {
        unsafe {
            let mut d: $t = std::mem::uninitialized();
            r.read_exact(d.as_mut())?;
            Ok(d)
        }
    }
}

}
}

marshal!(Addr);
marshal!(WgDevice);
marshal!(WgPeer);
marshal!(WgIpMask);
marshal!(WgEndpoint);

// Std types <-> C types.
