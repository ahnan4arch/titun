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

extern crate rustc_serialize;
extern crate serde_yaml;
extern crate log;

use std::convert::From;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum TiTunError {
    IoErr(io::Error),
    OtherErr(String),
}

impl Display for TiTunError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            TiTunError::IoErr(ref e) => write!(f, "IO Error: {}", e),
            TiTunError::OtherErr(ref e) => e.fmt(f),
        }
    }
}

impl Error for TiTunError {
    fn description(&self) -> &str {
        match *self {
            TiTunError::IoErr(ref e) => e.description(),
            TiTunError::OtherErr(ref e) => e.as_str(),
        }
    }
}

impl From<io::Error> for TiTunError {
    fn from(e: io::Error) -> TiTunError {
        TiTunError::IoErr(e)
    }
}

impl<'a> From<&'a str> for TiTunError {
    fn from(e: &'a str) -> TiTunError {
        TiTunError::OtherErr(e.to_string())
    }
}

impl From<String> for TiTunError {
    fn from(e: String) -> TiTunError {
        TiTunError::OtherErr(e)
    }
}

// It is not possible to
//
// impl<T> From<T> TiTunError where T: Error {
// }

macro_rules! impl_from_err {
    ($ty:ty) => (
        impl From<$ty> for TiTunError
        {
            fn from(e: $ty) -> TiTunError {
                TiTunError::OtherErr(e.description().to_string())
            }
        }
    )
}

impl_from_err!(::std::net::AddrParseError);
impl_from_err!(::std::num::ParseIntError);
impl_from_err!(self::log::SetLoggerError);
impl_from_err!(self::rustc_serialize::base64::FromBase64Error);
impl_from_err!(self::serde_yaml::Error);

pub type Result<T> = ::std::result::Result<T, TiTunError>;
