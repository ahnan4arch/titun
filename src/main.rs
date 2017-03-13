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

// Using system allocator seems to dramatically reduce memory footprint.
// (RSS ~20MiB -> ~3MiB!)
#![feature(alloc_system)]
extern crate alloc_system;

extern crate clap;
extern crate env_logger;
extern crate titun;
extern crate rustc_serialize;

use clap::{App, AppSettings, SubCommand};
use rustc_serialize::base64::{FromBase64, STANDARD, ToBase64};
use std::fs::File;
use std::io::{Read, stdin};
use titun::config::Config;
use titun::error::Result;
use titun::run::run;
use titun::wireguard::re_exports::{DH, U8Array, X25519};

fn read_file(path: &str) -> Result<String> {
    let mut f = File::open(path)?;
    let mut out = String::new();
    f.read_to_string(&mut out)?;
    Ok(out)
}

fn inner() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init()?;

    let sub_tun = SubCommand::with_name("tun")
        .display_order(1)
        .args_from_usage("-c, --config=<FILE> 'Specify config file'");
    let sub_genkey = SubCommand::with_name("genkey").display_order(2);
    let sub_pubkey = SubCommand::with_name("pubkey").display_order(3);

    let app = App::new("titun")
        .version("0.0.4")
        .about("A simple secure ip tunnel for linux.")
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(sub_tun)
        .subcommand(sub_genkey)
        .subcommand(sub_pubkey);

    let matches = app.get_matches();

    match matches.subcommand() {
        ("genkey", _) => {
            println!("{}",
                     <X25519 as DH>::genkey().as_slice().to_base64(STANDARD));
        }
        ("pubkey", _) => {
            let mut buffer = String::new();
            stdin().read_to_string(&mut buffer)?;
            let k = buffer.from_base64()?;
            if k.len() == 32 {
                let k = <X25519 as DH>::Key::from_slice(&k);
                let pk = <X25519 as DH>::pubkey(&k);
                println!("{}", pk.as_slice().to_base64(STANDARD));
            } else {
                return Err(From::from("Expect base64 encoded 32-byte X25519 secret key."));
            }
        }
        ("tun", Some(m)) => {
            let config_file = m.value_of("config").unwrap();
            let config = read_file(config_file)?;
            let config = Config::parse(config.as_str())?;
            run(config)?;
        }
        _ => {
            unreachable!();
        }
    }

    Ok(())
}

fn main() {
    inner().unwrap_or_else(|e| {
        println!("Error: {}", e);
        std::process::exit(1);
    })
}
