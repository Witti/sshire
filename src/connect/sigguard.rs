//! Protection against Ctrl-C while a child process (ssh) runs in the foreground.
//!
//! Background: the terminal sends Ctrl-C (SIGINT) and Ctrl-\ (SIGQUIT) to
//! the *entire foreground process group* - that is, to sshire **and** to
//! the ssh child. Without a countermeasure sshire would die immediately and
//! could no longer finish the log entry. As with `system(3)`, the rule during
//! a session is therefore: sshire survives the signal, ssh receives it normally.
//!
//! Important: do *not* set `SIG_IGN`. "Ignored" is inherited across `exec` by
//! the new program, so ssh could no longer be interrupted with Ctrl-C.
//! A *handler*, on the other hand, is automatically reset to the default on
//! `exec`, so ssh behaves as usual.
//!
//! Implementation with `signal-hook`: on first use, two actions are installed
//! per signal (they stay in place for the whole process, because an installed
//! handler cannot be cleanly removed):
//! 1. "Run the default behaviour if `terminate` = true" (terminates sshire),
//! 2. "Set a flag" (a no-op handler that swallows the signal).
//!
//! The [`SignalGuard`] switches `terminate` off and back on via RAII (Drop).
//! Outside a connection, Ctrl-C therefore terminates sshire as usual.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use signal_hook::consts::{SIGINT, SIGQUIT};
use signal_hook::flag;

/// Process-wide state: the `terminate` flag and the number of active guards.
struct Shared {
    terminate: Arc<AtomicBool>,
    // Several guards at once (e.g. parallel tests) must not release each
    // other, so we count them under a mutex.
    active: Mutex<usize>,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

/// Installs the handlers on first call and returns the state.
fn shared() -> io::Result<&'static Shared> {
    if let Some(s) = SHARED.get() {
        return Ok(s);
    }
    // Initially `true`: Ctrl-C terminates sshire as usual.
    let terminate = Arc::new(AtomicBool::new(true));
    // A second flag that is never read: all that matters is that a handler
    // exists that "consumes" the signal.
    let swallowed = Arc::new(AtomicBool::new(false));
    for sig in [SIGINT, SIGQUIT] {
        flag::register_conditional_default(sig, Arc::clone(&terminate))?;
        flag::register(sig, Arc::clone(&swallowed))?;
    }
    // In a race the first `set` wins; the second set of handlers then stays
    // ineffective because its `terminate` flag remains `true` - this is
    // harmless, since sshire only starts connections single-threaded.
    let _ = SHARED.set(Shared {
        terminate,
        active: Mutex::new(0),
    });
    SHARED
        .get()
        .ok_or_else(|| io::Error::other("signal state not initialized"))
}

/// RAII guard: as long as it lives, sshire survives SIGINT/SIGQUIT.
///
/// RAII = "Resource Acquisition Is Initialization": the cleanup lives in
/// `Drop::drop`, which Rust *always* calls when the scope ends - even on an
/// early `return` or `?`.
#[derive(Debug)]
pub struct SignalGuard {
    // Prevents building the guard from outside without `new`.
    _private: (),
}

impl SignalGuard {
    /// Activates the protection (installs the handlers on first use).
    pub fn new() -> io::Result<Self> {
        let shared = shared()?;
        // `lock()` can only fail on a "poisoned" mutex (a panic in another
        // thread); we use the counter anyway.
        let mut active = shared.active.lock().unwrap_or_else(|e| e.into_inner());
        *active += 1;
        shared.terminate.store(false, Ordering::SeqCst);
        Ok(Self { _private: () })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        if let Some(shared) = SHARED.get() {
            let mut active = shared.active.lock().unwrap_or_else(|e| e.into_inner());
            *active = active.saturating_sub(1);
            if *active == 0 {
                // Last guard gone: Ctrl-C terminates sshire again.
                shared.terminate.store(true, Ordering::SeqCst);
            }
        }
    }
}
