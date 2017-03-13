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

extern crate byteorder;
extern crate noise_protocol;
extern crate noise_sodiumoxide;
extern crate sodiumoxide;
extern crate tai64;
extern crate treebitmap;

use self::byteorder::{ByteOrder, LittleEndian};
use self::noise_protocol::Cipher;
use self::noise_sodiumoxide::ChaCha20Poly1305;
use self::sodiumoxide::randombytes::randombytes_into;
use self::tai64::TAI64N;
use self::treebitmap::{IpLookupTable, IpLookupTableOps};
use std::collections::HashMap;
use std::mem::uninitialized;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::Ordering::Relaxed;
use std::thread::{Builder, JoinHandle, spawn};
use std::time::{Duration, Instant};
use tun::Tun;
use wireguard::*;

// Increase if your MTU is larger...
const BUFSIZE: usize = 1500;

type SharedPeerState = Arc<RwLock<PeerState>>;

// Locking order:
//
//   info > peers > id_map

pub struct WgState {
    info: RwLock<WgInfo>,

    pubkey_map: RwLock<HashMap<X25519Pubkey, SharedPeerState>>,
    id_map: RwLock<HashMap<Id, SharedPeerState>>,
    // Also should be keep in sync. But these should change less often.
    rt4: RwLock<IpLookupTable<Ipv4Addr, SharedPeerState>>,
    rt6: RwLock<IpLookupTable<Ipv6Addr, SharedPeerState>>,

    // The secret used to calc cookie.
    cookie_secret: Mutex<([u8; 32], Instant)>,

    timer_controller: TimerController,
}

/// Removes `Id` from `id_map` when dropped.
struct IdMapGuard {
    wg: Arc<WgState>,
    id: Id,
}

impl Drop for IdMapGuard {
    fn drop(&mut self) {
        if let Ok(mut id_map) = self.wg.id_map.try_write() {
            id_map.remove(&self.id);
        } else {
            let wg = self.wg.clone();
            let id = self.id;
            spawn(move || { wg.id_map.write().unwrap().remove(&id); });
        }
    }
}

impl IdMapGuard {
    fn new(wg: Arc<WgState>, id: Id) -> Self {
        Self { wg: wg, id: id }
    }
}

pub struct PeerState {
    info: PeerInfo,
    last_handshake: Option<TAI64N>,
    cookie: Option<(Cookie, Instant)>,
    last_mac1: Option<[u8; 16]>,
    handshake: Option<Handshake>,

    // XXX: use a Vec? or ArrayVec?
    transport0: Option<Transport>,
    transport1: Option<Transport>,
    transport2: Option<Transport>,

    // Rekey because of REKEY_AFTER_TIME.
    rekey_after_time: TimerHandle,
    // Rekey because of send but not recv in...
    rekey_no_recv: TimerHandle,
    // Keep alive because of recv but not send in...
    keep_alive: TimerHandle,
    // Persistent keep-alive.
    persistent_keep_alive: TimerHandle,
    // Clear all sessions if no new handshake in REJECT_AFTER_TIME * 3.
    clear: TimerHandle,
}

struct Handshake {
    self_id: IdMapGuard,
    hs: HS,
    // Resend after REKEY_TIMEOUT.
    #[allow(dead_code)]
    resend: TimerHandle,
}

type SecretKey = <ChaCha20Poly1305 as Cipher>::Key;

/// A WireGuard transport session.
struct Transport {
    self_id: IdMapGuard,
    peer_id: Id,
    // If we are responder, should not send until received one packet.
    is_initiator_or_has_received: AtomicBool,
    // Also should not send after REJECT_AFTER_TIME,
    // or after REJECT_AFTER_MESSAGES.
    not_too_old: AtomicBool,
    created: Instant,

    send_key: SecretKey,
    send_counter: AtomicU64,

    recv_key: SecretKey,
    recv_ar: Mutex<AntiReplay>,
}

fn is_under_load() -> bool {
    false
}

fn udp_process_handshake_init(wg: Arc<WgState>, sock: &UdpSocket, p: &[u8], addr: SocketAddr) {
    if p.len() != 148 {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();

    if is_under_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), addr.to_string().as_bytes());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = &p[116..132];
            let reply = cookie_reply(info.psk.as_ref(), &info.pubkey, &cookie, peer_id, mac1);
            sock.send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    if let Ok(mut r) = process_initiation(info.deref(), p) {
        let r_pubkey = r.handshake_state.get_rs().unwrap();
        if let Some(peer0) = wg.find_peer_by_pubkey(&r_pubkey) {
            // Lock peer.
            let mut peer = peer0.write().unwrap();

            // Compare timestamp.
            if Some(r.timestamp) > peer.last_handshake {
                peer.last_handshake = Some(r.timestamp);
            } else {
                debug!("Handshake timestamp smaller.");
                return;
            }

            let self_id = Id::gen();
            let mut response = responde(info.deref(), &mut r, self_id);

            // Save mac1.
            let mut mac1 = [0u8; 16];
            mac1.copy_from_slice(&response[60..76]);
            peer.last_mac1 = Some(mac1);

            cookie_sign(&mut response, peer.get_cookie());
            sock.send_to(&response, addr).unwrap();

            let t = Transport::new_from_hs(IdMapGuard::new(wg.clone(), self_id),
                                           r.peer_id,
                                           r.handshake_state);
            peer.set_endpoint(addr);
            peer.push_transport(t, false);
            // Lock id_map.
            wg.id_map.write().unwrap().insert(self_id, peer0.clone());
            debug!("Handshake successful as responder.");
        } else {
            debug!("Get handshake init, but can't find peer by pubkey.");
        }
    } else {
        debug!("Get handshake init, but authentication/decryption failed.");
    }
}

fn udp_process_handshake_resp(wg: &WgState, sock: &UdpSocket, p: &[u8], addr: SocketAddr) {
    if p.len() != 92 {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();

    if is_under_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), addr.to_string().as_bytes());
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = &p[60..76];
            let reply = cookie_reply(info.psk.as_ref(), &info.pubkey, &cookie, peer_id, mac1);
            sock.send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    let self_id = Id::from_slice(&p[8..12]);

    if let Some(peer0) = wg.find_peer_by_id(self_id) {
        let (peer_id, hs) = {
            // Lock peer.
            let peer = peer0.read().unwrap();
            if peer.handshake.is_none() {
                debug!("Get handshake response message, but don't know id.");
                return;
            }
            let handshake = peer.handshake.as_ref().unwrap();
            if handshake.self_id.id != self_id {
                debug!("Get handshake response message, but don't know id.");
                return;
            }

            let mut hs = handshake.hs.clone();
            if let Ok(peer_id) = process_response(info.deref(), &mut hs, p) {
                (peer_id, hs)
            } else {
                debug!("Get handshake response message, auth/decryption failed.");
                return;
            }
            // Release peer.
        };
        debug!("Handshake successful as initiator.");
        // Lock peer.
        let mut peer = peer0.write().unwrap();
        let handle = peer.handshake.take().unwrap().self_id;
        let t = Transport::new_from_hs(handle, peer_id, hs);
        peer.push_transport(t, true);
        peer.set_endpoint(addr);
        // Send an empty packet for key confirmation.
        do_keep_alive(&peer, sock);
        // Lock id_map.
        wg.id_map.write().unwrap().insert(self_id, peer0.clone());
    } else {
        debug!("Get handshake response message, but don't know id.");
    }
}

fn udp_process_cookie_reply(wg: &WgState, p: &[u8]) {
    let self_id = Id::from_slice(&p[4..8]);

    // Lock info.
    let info = wg.info.read().unwrap();

    if let Some(peer) = wg.find_peer_by_id(self_id) {
        // Lock peer.
        let mut peer = peer.write().unwrap();
        if let Some(mac1) = peer.last_mac1 {
            if let Ok(cookie) = process_cookie_reply(info.psk.as_ref(),
                                                     &peer.info.peer_pubkey,
                                                     &mac1,
                                                     p) {
                peer.cookie = Some((cookie, Instant::now()));
            } else {
                debug!("Process cookie reply: auth/decryption failed.");
            }
        }
    }
}

fn udp_process_transport(wg: &WgState, tun: &Tun, p: &[u8], addr: SocketAddr) {
    if p.len() < 32 {
        return;
    }

    let self_id = Id::from_slice(&p[4..8]);

    let maybe_peer0 = wg.find_peer_by_id(self_id);

    if maybe_peer0.is_none() {
        debug!("Get transport message, but don't know id.");
        return;
    }

    let peer0 = maybe_peer0.unwrap();
    let should_set_endpoint = {
        // Lock peer.
        let peer = peer0.read().unwrap();
        if let Some(t) = peer.find_transport_by_id(self_id) {
            let mut buff: [u8; BUFSIZE] = unsafe { uninitialized() };
            let decrypted = &mut buff[..p.len() - 32];
            if t.decrypt(p, decrypted).is_ok() {
                if let Ok((len, src, _)) = parse_ip_packet(decrypted) {
                    // Reverse path filtering.
                    let peer1 = wg.find_peer_by_ip(src);
                    if peer1.is_none() || !Arc::ptr_eq(&peer0, &peer1.unwrap()) {
                        debug!("Get transport message: allowed IPs check failed.");
                    } else {
                        tun.write(&decrypted[..len as usize]).unwrap();
                    }
                }
                if decrypted.len() > 0 {
                    peer.on_recv();
                } else {
                    // For keep-alive packet, only cancel re-key.
                    // I.e., do not activate keep-alive because of keep-alive.
                    peer.rekey_no_recv.de_activate();
                }
                peer.info.endpoint != Some(addr)
            } else {
                debug!("Get transport message, decryption failed.");
                false
            }
        } else {
            false
        }
        // Release peer.
    };
    if should_set_endpoint {
        // Lock peer.
        peer0.write()
            .unwrap()
            .set_endpoint(addr);
    }
}

/// Start a new thread to recv and process UDP packets.
///
/// This thread runs forever.
pub fn start_udp_processing(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("UDP".to_string()).spawn(move || {
        let mut p = [0u8; BUFSIZE];
        loop {
            let (len, addr) = sock.recv_from(&mut p).unwrap();

            if len < 12 {
                continue;
            }

            let type_ = p[0];
            let p = &p[..len];

            match type_ {
                1 => udp_process_handshake_init(wg.clone(), sock.as_ref(), p, addr),
                2 => udp_process_handshake_resp(wg.as_ref(), sock.as_ref(), p, addr),
                3 => udp_process_cookie_reply(wg.as_ref(), p),
                4 => udp_process_transport(wg.as_ref(), tun.as_ref(), p, addr),
                _ => (),
            }
        }
    }).unwrap()
}

// Packets >= MAX_PADDING won't be padded.
// 1280 should be a reasonable conservative choice.
const MAX_PADDING: usize = 1280;

const PADDING_MASK: usize = 0b1111;

fn pad_len(len: usize) -> usize {
    if len >= MAX_PADDING {
        len
    } else {
        // Next multiply of 16.
        (len & !PADDING_MASK) + if len & PADDING_MASK == 0 {
            0
        } else {
            16
        }
    }
}

#[cfg(test)]
#[test]
fn padding() {
    assert_eq!(pad_len(0), 0);
    for i in 1..16 {
        assert_eq!(pad_len(i), 16);
    }

    for i in 17..32 {
        assert_eq!(pad_len(i), 32);
    }

    for i in 1265..1280 {
        assert_eq!(pad_len(i), 1280);
    }
}

/// Start a new thread to read and process packets from TUN device.
///
/// This thread runs forever.
pub fn start_tun_packet_processing(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("TUN".to_string()).spawn(move || {
        let mut pkt = [0u8; BUFSIZE];
        loop {
            let len = tun.read(&mut pkt).unwrap();
            let padded_len = pad_len(len);
            // Do not leak other packets' data!
            for b in &mut pkt[len..padded_len] {
                *b = 0;
            }
            let pkt = &pkt[..padded_len];

            let parse_result = parse_ip_packet(pkt);
            if parse_result.is_err() {
                error!("Get packet from TUN device, but failed to parse it!");
                continue;
            }
            let dst = parse_result.unwrap().2;

            let peer = wg.find_peer_by_ip(dst);
            if peer.is_none() {
                // TODO ICMP no route to host.
                debug!("No route to host: {}", dst);
                continue;
            }
            let peer0 = peer.unwrap();
            let should_handshake = {
                // Lock peer.
                let peer = peer0.read().unwrap();
                if peer.get_endpoint().is_none() {
                    // TODO ICMP host unreachable?
                    continue;
                }

                let (t, should_handshake) = peer.find_transport_to_send();
                if let Some(t) = t {
                    let mut encrypted: [u8; BUFSIZE] = unsafe { uninitialized() };
                    let encrypted = &mut encrypted[..pkt.len() + 32];
                    if t.encrypt(pkt, encrypted).is_err() {
                        continue;
                    }
                    sock.send_to(encrypted, peer.get_endpoint().unwrap()).unwrap();
                    peer.on_send();
                    false
                } else {
                    should_handshake
                }
                // Release peer.
            };

            if should_handshake {
                do_handshake(wg.clone(), peer0, sock.clone());
            }
        }
    }).unwrap()
}

/// Start handshake.
///
/// Better not hold any locks when calling this.
//
/// Nothing happens if there is already an ongoing handshake for this peer.
/// Nothing happens if we don't know peer endpoint.
fn do_handshake(wg: Arc<WgState>, peer0: SharedPeerState, sock: Arc<UdpSocket>) {
    // Lock info.
    let info = wg.info.read().unwrap();

    // Lock peer.
    let mut peer = peer0.write().unwrap();
    if peer.handshake.is_some() {
        return;
    }
    let endpoint = if peer.get_endpoint().is_none() {
        return;
    } else {
        peer.get_endpoint().unwrap()
    };

    debug!("Handshake init.");

    let id = Id::gen();
    // Lock id_map.
    wg.id_map.write().unwrap().insert(id, peer0.clone());
    let handle = IdMapGuard::new(wg.clone(), id);

    let (mut i, hs) = initiate(info.deref(), &peer.info, id);
    cookie_sign(&mut i, peer.get_cookie());

    sock.send_to(&i, endpoint).unwrap();
    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&i[116..132]);
    peer.last_mac1 = Some(mac1);

    let resend = {
        let wg = wg.clone();
        let sock = sock.clone();
        let peer = Arc::downgrade(&peer0);
        Box::new(move || {
            debug!("Timer: resend.");
            peer.upgrade().map(|p| {
                p.write().unwrap().handshake = None;
                do_handshake(wg.clone(), p, sock.clone());
            });
        })
    };

    let resend = wg.timer_controller.register_delay(Duration::from_secs(REKEY_TIMEOUT), resend);
    resend.activate();

    peer.handshake = Some(Handshake {
        self_id: handle,
        hs: hs,
        resend: resend,
    });

    peer.clear.adjust_and_activate_if_not_activated(3 * REJECT_AFTER_TIME);
}

fn do_keep_alive(peer: &PeerState, sock: &UdpSocket) {
    let e = peer.get_endpoint();
    if e.is_none() {
        return;
    }
    let e = e.unwrap();

    let t = peer.find_transport_to_send().0;
    if t.is_none() {
        return;
    }
    let t = t.unwrap();

    let mut out = [0u8; 32];
    if t.encrypt(&[], &mut out).is_err() {
        return;
    }

    debug!("Keep alive.");
    sock.send_to(&out, e).unwrap();

    // We do not expect a reply for a keep-alive packet.
    // So do not activate rekey_no_recv.
    peer.keep_alive.de_activate();
    peer.info.keep_alive_interval.as_ref().map(|&i| {
        peer.persistent_keep_alive.adjust_and_activate(i as u64);
    });
}

// Cannot be a method because we need `Arc<WgState>`.
pub fn wg_add_peer(wg: Arc<WgState>, peer: &PeerInfo, sock: Arc<UdpSocket>) {
    let register = |a| wg.timer_controller.register(Instant::now(), a);
    let dummy_action = || Box::new(|| {});

    let mut pubkey_map = wg.pubkey_map.write().unwrap();

    let ps = PeerState {
        info: peer.clone(),
        last_handshake: None,
        last_mac1: None,
        cookie: None,
        handshake: None,
        transport0: None,
        transport1: None,
        transport2: None,
        rekey_after_time: register(dummy_action()),
        rekey_no_recv: register(dummy_action()),
        keep_alive: register(dummy_action()),
        persistent_keep_alive: register(dummy_action()),
        clear: register(dummy_action()),
    };
    let ps = Arc::new(RwLock::new(ps));

    // Init timers.
    {
        let weak_ps = Arc::downgrade(&ps);
        let mut psw = ps.write().unwrap();
        psw.rekey_after_time = {
            let wg = wg.clone();
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: rekey after time.");
                    do_handshake(wg.clone(), p, sock.clone());
                });
            }))
        };
        // Same with rekey.
        psw.rekey_no_recv = {
            let wg = wg.clone();
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: rekey_no_recv.");
                    do_handshake(wg.clone(), p, sock.clone());
                });
            }))
        };
        psw.keep_alive = {
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: keep_alive.");
                    do_keep_alive(&p.read().unwrap(), &sock);
                });
            }))
        };
        psw.persistent_keep_alive = {
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: persistent_keep_alive.");
                    do_keep_alive(&p.read().unwrap(), &sock);
                });
            }))
        };
        psw.clear = {
            let weak_ps = weak_ps.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: clear.");
                    p.write().unwrap().clear();
                });
            }))
        };
    }

    let mut rt4 = wg.rt4.write().unwrap();
    let mut rt6 = wg.rt6.write().unwrap();

    for &(a, prefix) in &peer.allowed_ips {
        match a {
            IpAddr::V4(a4) => rt4.insert(a4, prefix, ps.clone()),
            IpAddr::V6(a6) => rt6.insert(a6, prefix, ps.clone()),
        };
    }
    pubkey_map.insert(peer.peer_pubkey, ps);
}

impl WgState {
    pub fn new(info: WgInfo) -> WgState {
        let mut cookie = [0u8; 32];
        randombytes_into(&mut cookie);

        WgState {
            info: RwLock::new(info),
            pubkey_map: RwLock::new(HashMap::with_capacity(1)),
            id_map: RwLock::new(HashMap::with_capacity(4)),
            rt4: RwLock::new(IpLookupTable::new()),
            rt6: RwLock::new(IpLookupTable::new()),
            cookie_secret: Mutex::new((cookie, Instant::now())),
            timer_controller: TimerController::new(),
        }
    }

    pub fn new_with_peers(info: WgInfo, peers: &[PeerInfo], sock: Arc<UdpSocket>) -> Arc<WgState> {
        let wg = Arc::new(WgState::new(info));

        for p in peers {
            wg_add_peer(wg.clone(), p, sock.clone())
        }

        wg
    }

    // This methods helps a lot in avoiding deadlocks.

    fn find_peer_by_id(&self, id: Id) -> Option<SharedPeerState> {
        self.id_map.read().unwrap().get(&id).cloned()
    }

    fn find_peer_by_pubkey(&self, pk: &X25519Pubkey) -> Option<SharedPeerState> {
        self.pubkey_map.read().unwrap().get(pk).cloned()
    }

    /// Find peer by ip address, consulting the routing tables.
    fn find_peer_by_ip(&self, addr: IpAddr) -> Option<SharedPeerState> {
        match addr {
            IpAddr::V4(ip4) => {
                self.rt4
                    .read()
                    .unwrap()
                    .longest_match(ip4)
                    .map(|x| x.2.clone())
            }
            IpAddr::V6(ip6) => {
                self.rt6
                    .read()
                    .unwrap()
                    .longest_match(ip6)
                    .map(|x| x.2.clone())
            }
        }
    }

    fn get_cookie_secret(&self) -> [u8; 32] {
        let mut cs = self.cookie_secret.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(cs.1) <= Duration::from_secs(120) {
            cs.0
        } else {
            randombytes_into(&mut cs.0);
            cs.1 = now;
            cs.0
        }
    }
}

impl PeerState {
    fn get_endpoint(&self) -> Option<SocketAddr> {
        self.info.endpoint
    }

    fn set_endpoint(&mut self, a: SocketAddr) {
        self.info.endpoint = Some(a)
    }

    fn get_cookie(&self) -> Option<&Cookie> {
        if self.cookie.is_none() {
            return None;
        }
        if self.cookie.as_ref().unwrap().1.elapsed() >= Duration::from_secs(120) {
            return None;
        }
        Some(&self.cookie.as_ref().unwrap().0)
    }

    fn clear(&mut self) {
        self.handshake = None;
        self.transport0 = None;
        self.transport1 = None;
        self.transport2 = None;

        self.rekey_after_time.de_activate();
        self.rekey_no_recv.de_activate();
        self.keep_alive.de_activate();
        self.persistent_keep_alive.de_activate();
        self.clear.de_activate();
    }

    // rekey = is_initiator.
    fn on_new_transport(&self, rekey: bool) {
        if rekey {
            self.rekey_after_time.adjust_and_activate(REKEY_AFTER_TIME);
        } else {
            self.rekey_after_time.de_activate();
        }
        self.clear.adjust_and_activate(3 * REJECT_AFTER_TIME);
        self.info.keep_alive_interval.as_ref().map(|i| {
            self.persistent_keep_alive.adjust_and_activate(*i as u64);
        });
    }

    fn on_recv(&self) {
        self.rekey_no_recv.de_activate();
        self.keep_alive.adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT);
    }

    fn on_send(&self) {
        self.keep_alive.de_activate();
        self.rekey_no_recv.adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        self.info.keep_alive_interval.as_ref().map(|i| {
            self.persistent_keep_alive.adjust_and_activate(*i as u64);
        });
    }

    fn push_transport(&mut self, t: Transport, is_initiator: bool) {
        self.on_new_transport(is_initiator);

        self.transport2 = self.transport1.take();
        self.transport1 = self.transport0.take();
        self.transport0 = Some(t);
    }

    /// Find a transport to send packet. And indicate whether we should initiate handshake.
    fn find_transport_to_send(&self) -> (Option<&Transport>, bool) {
        // If there exists any transport, we rely on timers to init handshake.

        if let Some(ref t) = self.transport0 {
            if t.get_should_send() {
                return (Some(t), false);
            }
        } else {
            return (None, true);
        }

        if let Some(ref t) = self.transport1 {
            if t.get_should_send() {
                return (Some(t), false);
            }
        } else {
            return (None, false);
        }

        if let Some(ref t) = self.transport2 {
            if t.get_should_send() {
                return (Some(t), false);
            }
        }

        (None, false)
    }

    fn find_transport_by_id(&self, id: Id) -> Option<&Transport> {
        if let Some(ref t) = self.transport0 {
            if t.get_self_id() == id {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport1 {
            if t.get_self_id() == id {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport2 {
            if t.get_self_id() == id {
                return Some(t);
            }
        }
        None
    }
}

impl Transport {
    fn new_from_hs(self_id: IdMapGuard, peer_id: Id, hs: HS) -> Self {
        let (x, y) = hs.get_ciphers();
        let (s, r) = if hs.get_is_initiator() {
            (x, y)
        } else {
            (y, x)
        };
        let sk = s.extract().0;
        let rk = r.extract().0;

        Transport {
            self_id: self_id,
            peer_id: peer_id,
            is_initiator_or_has_received: AtomicBool::new(hs.get_is_initiator()),
            not_too_old: AtomicBool::new(true),
            send_key: sk,
            recv_key: rk,
            created: Instant::now(),
            recv_ar: Mutex::new(AntiReplay::new()),
            send_counter: AtomicU64::new(0),
        }
    }

    fn get_should_send(&self) -> bool {
        self.is_initiator_or_has_received.load(Relaxed) && self.not_too_old.load(Relaxed)
    }

    fn get_self_id(&self) -> Id {
        self.self_id.id
    }

    /// Expect packet with padding.
    ///
    /// Length: out.len() = msg.len() + 32.
    fn encrypt(&self, msg: &[u8], out: &mut [u8]) -> Result<(), ()> {
        let c = self.send_counter.fetch_add(1, Relaxed);
        if c >= REJECT_AFTER_MESSAGES {
            self.not_too_old.store(false, Relaxed);
            return Err(());
        }
        if self.created.elapsed() >= Duration::from_secs(REJECT_AFTER_TIME) {
            self.not_too_old.store(false, Relaxed);
            return Err(());
        }

        out[0..4].copy_from_slice(&[4, 0, 0, 0]);
        out[4..8].copy_from_slice(self.peer_id.as_slice());
        LittleEndian::write_u64(&mut out[8..16], c);

        <ChaCha20Poly1305 as Cipher>::encrypt(&self.send_key, c, &[], msg, &mut out[16..]);

        Ok(())
    }

    /// Returns packet maybe with padding.
    ///
    /// Length: out.len() + 32 = msg.len().
    fn decrypt(&self, msg: &[u8], out: &mut [u8]) -> Result<(), ()> {
        if self.created.elapsed() >= Duration::from_secs(REJECT_AFTER_TIME) {
            return Err(());
        }

        if msg.len() < 32 {
            return Err(());
        }

        if msg[0..4] != [4, 0, 0, 0] {
            return Err(());
        }

        if self.created.elapsed() >= Duration::from_secs(REJECT_AFTER_TIME) {
            return Err(());
        }

        let counter = LittleEndian::read_u64(&msg[8..16]);

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(());
        }

        <ChaCha20Poly1305 as Cipher>::decrypt(&self.recv_key, counter, &[], &msg[16..], out)?;

        if !self.recv_ar.lock().unwrap().check_and_update(counter) {
            return Err(());
        }

        self.is_initiator_or_has_received.store(true, Relaxed);

        Ok(())
    }
}
