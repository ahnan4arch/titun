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

use std::mem::replace;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::AtomicBool;
// Play safe for now.
use std::sync::atomic::Ordering::{Relaxed, Acquire, Release};
use std::thread;
use std::time::{Duration, Instant};

type Action = Box<Fn() + Send + Sync>;

pub struct TimerHandle(Arc<Timer>);

struct Timer {
    activated: AtomicBool,
    at: Mutex<Instant>,
    action: Action,
}

// This timer should be OK for a small number of peers/timers.
// But it is slow for a large number of peers/timers.

/// Optimised for activation/de-activation and adjustment of a
/// mostly fixed set of timers.
pub struct TimerController {
    timers: Arc<Mutex<Vec<Weak<Timer>>>>,
}

impl TimerController {
    pub fn new() -> Self {
        let timers: Arc<Mutex<Vec<Weak<Timer>>>> = Arc::new(Mutex::new(Vec::new()));
        let timers1 = timers.clone();
        thread::Builder::new()
            .name("timer".to_string())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));

                    let mut timers = timers1.lock().unwrap();
                    let now = Instant::now();

                    let old_timers = replace(timers.deref_mut(), Vec::new());
                    // Avoid deadlock.
                    drop(timers);

                    let mut alive_timers = old_timers.into_iter()
                        .filter_map(|t0| if let Some(t) = t0.upgrade() {
                            if t.activated.load(Acquire) && t.at.lock().unwrap().le(&now) {
                                t.activated.store(false, Relaxed);
                                (t.action)();
                            }
                            Some(t0)
                        } else {
                            None
                        })
                        .collect();

                    let mut timers = timers1.lock().unwrap();
                    timers.append(&mut alive_timers);
                }
            })
            .unwrap();
        Self { timers: timers }
    }

    pub fn register(&self, at: Instant, action: Action) -> TimerHandle {
        let t = Timer {
            activated: AtomicBool::new(false),
            at: Mutex::new(at),
            action: action,
        };
        let handle = Arc::new(t);
        self.timers.lock().unwrap().push(Arc::downgrade(&handle));
        TimerHandle(handle)
    }

    pub fn register_delay(&self, delay: Duration, action: Action) -> TimerHandle {
        self.register(Instant::now() + delay, action)
    }
}

impl TimerHandle {
    pub fn activate(&self) {
        self.0.activated.store(true, Release);
    }

    pub fn de_activate(&self) {
        self.0.activated.store(false, Relaxed);
    }

    pub fn adjust_to(&self, at: Instant) {
        *self.0.at.lock().unwrap() = at;
    }

    pub fn adjust_and_activate(&self, secs: u64) {
        self.adjust_to(Instant::now() + Duration::from_secs(secs));
        // Activate after adjust.
        self.activate();
    }

    pub fn adjust_and_activate_if_not_activated(&self, secs: u64) {
        if !self.0.activated.load(Relaxed) {
            self.adjust_to(Instant::now() + Duration::from_secs(secs));
            self.0.activated.store(true, Release);
        }
    }
}
