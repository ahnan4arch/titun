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

use std::ffi::OsStr;
use std::io::{Error, ErrorKind, Read, Result, copy};
use std::process::{Command, Stdio};

pub struct ScriptRunner {
    c: Command,
}

impl Default for ScriptRunner {
    fn default() -> Self {
        ScriptRunner::new()
    }
}

impl ScriptRunner {
    pub fn new() -> ScriptRunner {
        ScriptRunner { c: Command::new("sh") }
    }

    pub fn env<K, V>(mut self, key: K, val: V) -> ScriptRunner
        where K: AsRef<OsStr>,
              V: AsRef<OsStr>
    {
        self.c.env(key, val);
        self
    }

    pub fn run<R>(mut self, mut r: R) -> Result<()>
        where R: Read
    {
        let mut p = self.c
            .stdin(Stdio::piped())
            .spawn()?;
        copy(&mut r, p.stdin.as_mut().unwrap())?;
        let r = p.wait()?;
        if r.success() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "running config script failed"))
        }
    }
}
