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

extern crate noise_protocol;
extern crate noise_sodiumoxide;
extern crate sodiumoxide;

use self::noise_protocol::DH;
use self::noise_sodiumoxide::X25519;
use self::sodiumoxide::randombytes::randombytes_into;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;

pub type X25519Key = <X25519 as DH>::Key;
pub type X25519Pubkey = <X25519 as DH>::Pubkey;

/// Config info about a WireGuard peer.
#[derive(Clone)]
pub struct PeerInfo {
    pub peer_pubkey: X25519Pubkey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    // Valid values: 1 - 0xfffe.
    pub keep_alive_interval: Option<u16>,
}

/// Config info about a WireGuard interface.
pub struct WgInfo {
    pub psk: Option<[u8; 32]>,
    pub key: X25519Key,
    // pubkey == X25519::pubkey(&key)
    pub pubkey: X25519Pubkey,
}

impl WgInfo {
    pub fn new(psk: Option<[u8; 32]>, key: X25519Key) -> Self {
        let pk = <X25519 as DH>::pubkey(&key);
        WgInfo {
            psk: psk,
            key: key,
            pubkey: pk,
        }
    }
}

/// Sender index or receiver index.
///
/// WireGuard treats an index as a `u32` in little endian.
/// Why not just treat it as a 4-byte array?
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Id(pub [u8; 4]);

impl Id {
    /// Generate a new random ID.
    pub fn gen() -> Id {
        let mut id = [0u8; 4];
        randombytes_into(&mut id);
        Id(id)
    }

    /// Create Id from a slice.
    ///
    /// # Panics
    ///
    /// Slice must be 4 bytes long.
    pub fn from_slice(id: &[u8]) -> Id {
        let mut ret = Id([0u8; 4]);
        ret.0.copy_from_slice(id);
        ret
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Id {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

// Constants.

// That is, 2 ^ 64 - 2 ^ 16 - 1;
pub const REKEY_AFTER_MESSAGES: u64 = 0xfffffffffffeffff;
// That is, 2 ^ 64 - 2 ^ 4 - 1;
pub const REJECT_AFTER_MESSAGES: u64 = 0xffffffffffffffef;

// Timers, in seconds.

pub const REKEY_AFTER_TIME: u64 = 120;
pub const REJECT_AFTER_TIME: u64 = 180;
pub const REKEY_ATTEMPT_TIME: u64 = 90;
pub const REKEY_TIMEOUT: u64 = 5;
pub const KEEPALIVE_TIMEOUT: u64 = 10;
