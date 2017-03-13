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

// Handshake messages generation and parsing.
mod handshake;
// Anti-Replay algorithm.
mod anti_replay;
// Cookie reply messages generation and parsing.
mod cookie;
// Common types.
mod types;
// IP packet parsing.
mod ip;
// The timer state machine, and actual IO stuff.
mod controller;
// WireGuard UAPI.
mod uapi;
// A generic timer, but optimised for operations mostly used in WG.
mod timer;

/// Re-export some types and functions from other crates, so users
/// of this module won't have to manually pull in all these crates.
pub mod re_exports;

pub use self::anti_replay::*;
pub use self::controller::*;
pub use self::cookie::*;
pub use self::handshake::*;
pub use self::ip::*;
pub use self::timer::*;
pub use self::types::*;
pub use self::uapi::*;
