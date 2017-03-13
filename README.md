# TiTun

[![Build Status](https://travis-ci.org/sopium/titun.svg?branch=master)](https://travis-ci.org/sopium/titun)

Work in progress WireGuard implementation in Rust.

It is nowhere near complete/stable/secure. But basic functionality seems to work.

Review and testing is welcome.

## TODO

### Protocol

* ICMP no route to host / unreachable reply.
* Queue packets during handshake initiation.

### Cross Platform

* Support more platforms, i.e., write TUN device wrappers for more platforms.

### UI

* Work with the `wg` tool, i.e., impl [this](https://www.wireguard.io/xplatform/).

### Testing

* More tests.

### Performance

* Implement a more efficient timer.
* Other possible performance improvements.
