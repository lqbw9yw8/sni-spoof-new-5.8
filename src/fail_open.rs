//! Fail-open panic/error boundary used by the capture loop. [DONE]
//! Lives in a cfg-free module so the tests run on every OS (they used to
//! sit inside `engine.rs`, which is `cfg(windows)` only).

use crate::error::DpiGuardError;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// What the capture loop should do with a diverted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireAction {
    /// Inject these packets in order (50µs gap between them).
    Send(Vec<Vec<u8>>),
    /// Send nothing now (reassembly is holding the bytes).
    Hold,
}

/// Run `f(original)`. On panic **or** `Err`, log and return the original
/// packet so a mutation bug never black-holes the user's connection.
pub fn handle_exception_fail_open<F>(original: &[u8], f: &mut F) -> WireAction
where
    F: FnMut(Vec<u8>) -> Result<WireAction, DpiGuardError>,
{
    // Hot path: this runs once per captured packet. `original.to_vec()`
    // used to happen twice unconditionally here (once to feed the
    // closure, once as a pre-built fallback copy), on top of the copy
    // the capture loop already makes and whatever the pipeline itself
    // allocates for a pass-through packet — up to 4 heap allocations +
    // memcpys per packet before this fix. The fallback copy is only
    // actually needed on the empty-Send / Err / panic branches (rare),
    // so each of those branches now calls `original.to_vec()` inline,
    // only when it's actually taken, instead of building one unnamed
    // copy upfront on every packet.
    let original_owned = original.to_vec();
    match catch_unwind(AssertUnwindSafe(|| f(original_owned))) {
        Ok(Ok(WireAction::Send(packets))) if !packets.is_empty() => WireAction::Send(packets),
        Ok(Ok(WireAction::Send(_))) => WireAction::Send(vec![original.to_vec()]),
        Ok(Ok(WireAction::Hold)) => WireAction::Hold,
        Ok(Err(e)) => {
            log::error!("mutation returned error, passing original packet through: {e}");
            WireAction::Send(vec![original.to_vec()])
        }
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .or_else(|| panic_payload.downcast_ref::<Box<str>>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            log::error!("mutation panicked, passing original packet through: {msg}");
            WireAction::Send(vec![original.to_vec()])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_open_returns_original_on_panic() {
        let original = vec![1, 2, 3];
        let mut f = |_: Vec<u8>| -> Result<WireAction, DpiGuardError> { panic!("boom") };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_returns_mutated_on_success() {
        let original = vec![1, 2, 3];
        let mut f = |mut v: Vec<u8>| -> Result<WireAction, DpiGuardError> {
            v.push(4);
            Ok(WireAction::Send(vec![v]))
        };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![vec![1, 2, 3, 4]]));
    }

    #[test]
    fn fail_open_returns_original_on_err() {
        let original = vec![9];
        let mut f = |_: Vec<u8>| -> Result<WireAction, DpiGuardError> {
            Err(DpiGuardError::SniNotFound)
        };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_empty_vec_becomes_original() {
        let original = vec![7, 8];
        let mut f = |_: Vec<u8>| -> Result<WireAction, DpiGuardError> {
            Ok(WireAction::Send(vec![]))
        };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_preserves_hold() {
        let original = vec![1];
        let mut f = |_: Vec<u8>| -> Result<WireAction, DpiGuardError> { Ok(WireAction::Hold) };
        assert_eq!(
            handle_exception_fail_open(&original, &mut f),
            WireAction::Hold
        );
    }
}
