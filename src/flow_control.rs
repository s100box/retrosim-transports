//! Flow-control emulation for byte-stream transports.
//!
//! The Transport trait's `ModemControl` interface models RS-232
//! RTS/CTS — but only `SerialTransport` has real hardware pins behind
//! it.  Network transports (SSH, TCP, telnet) are byte streams with no
//! out-of-band signaling, so a simulated UART's RTS bit normally has
//! nowhere to go, and any XON (0x11) / XOFF (0x13) bytes the firmware
//! emits travel to the remote as ordinary data. Whether the remote honors
//! them depends on its terminal settings and application.
//!
//! [`FlowControlGate`] bridges the semantic gap.  It is owned by each
//! network transport and combines two throttle sources that together
//! give a network transport real flow control:
//!
//! 1. **Software (XON/XOFF).** Outbound bytes are sniffed; XOFF pauses
//!    the read side until XON clears it.
//! 2. **Hardware (RTS/CTS).** The firmware's MCR RTS bit is routed
//!    into the gate via the transport's `ModemControl::set_rts` impl.
//!    De-asserting RTS (= "I'm full, stop sending") pauses reads too.
//!
//! When either source is paused, the transport returns `WouldBlock`
//! from `Read::read`.  TCP's own receive-window flow control then
//! naturally backpressures the remote — the only mechanism a byte-
//! stream transport actually has to throttle a sender.
//!
//! The gate is passive on the TX side: it never strips XON/XOFF from
//! the outbound stream.  If the remote happens to be another real
//! serial endpoint that honors those bytes, they still propagate
//! end-to-end.

use std::sync::atomic::{AtomicBool, Ordering};

/// ASCII DC3 — pause transmission (XOFF, `Ctrl-S`).
pub const XOFF: u8 = 0x13;
/// ASCII DC1 — resume transmission (XON, `Ctrl-Q`).
pub const XON: u8 = 0x11;

/// Combined software (XON/XOFF) + hardware (RTS/CTS) flow-control
/// gate for network transports.
///
/// Cheap to construct (two atomics + two bools); one per transport.
/// Pause flags use relaxed atomic ordering: they carry independent throttle
/// state and do not publish other data or synchronize access to a transport.
pub struct FlowControlGate {
    /// XON/XOFF-driven pause, set by `observe_outbound`.
    xoff_paused: AtomicBool,
    /// RTS-deasserted pause, set by `set_rts`.  Mirrors "firmware has
    /// cleared RTS" which in RS-232 land means "the simulated UART
    /// says stop sending".
    rts_deasserted: AtomicBool,
    /// Software flow-control enable.
    xon_xoff_enabled: bool,
    /// Hardware flow-control enable.
    rts_cts_enabled: bool,
}

impl FlowControlGate {
    /// Construct with both flow-control sources enabled. Stream transports
    /// use this default; a standalone gate can instead use [`Self::with_options`].
    /// Outbound XON/XOFF bytes pass through unchanged with either setting.
    pub fn new() -> Self {
        Self::with_options(true, true)
    }

    /// Construct with explicit enable flags for each source.
    pub fn with_options(xon_xoff_enabled: bool, rts_cts_enabled: bool) -> Self {
        Self {
            xoff_paused: AtomicBool::new(false),
            rts_deasserted: AtomicBool::new(false),
            xon_xoff_enabled,
            rts_cts_enabled,
        }
    }

    /// Enable/disable the XON/XOFF sniffer.  Disabling also clears a
    /// pending pause so the next read isn't spuriously blocked.
    pub fn set_xon_xoff_enabled(&mut self, enabled: bool) {
        self.xon_xoff_enabled = enabled;
        if !enabled {
            self.xoff_paused.store(false, Ordering::Relaxed);
        }
    }

    /// Enable/disable the RTS/CTS gate.  Disabling also clears the
    /// RTS-deasserted flag.
    pub fn set_rts_cts_enabled(&mut self, enabled: bool) {
        self.rts_cts_enabled = enabled;
        if !enabled {
            self.rts_deasserted.store(false, Ordering::Relaxed);
        }
    }

    /// `true` if the XON/XOFF sniffer is active.
    pub fn is_xon_xoff_enabled(&self) -> bool {
        self.xon_xoff_enabled
    }

    /// `true` if the RTS/CTS gate is active.
    pub fn is_rts_cts_enabled(&self) -> bool {
        self.rts_cts_enabled
    }

    /// Scan an outbound buffer for XOFF / XON.  Last-wins within the
    /// buffer — `[XOFF, _, XON]` ends unpaused.  Bytes are never
    /// removed or altered; this is a sniff, not a filter.
    pub fn observe_outbound(&self, buf: &[u8]) {
        if !self.xon_xoff_enabled {
            return;
        }
        for &b in buf {
            match b {
                XOFF => self.xoff_paused.store(true, Ordering::Relaxed),
                XON => self.xoff_paused.store(false, Ordering::Relaxed),
                _ => {}
            }
        }
    }

    /// Route the firmware-driven RTS line into the gate.  `active=true`
    /// (RTS asserted = "I can receive") permits reads; `active=false`
    /// (RTS de-asserted = "I'm full") pauses them.
    pub fn set_rts(&self, active: bool) {
        if !self.rts_cts_enabled {
            return;
        }
        self.rts_deasserted.store(!active, Ordering::Relaxed);
    }

    /// `true` when any throttle source is active.  Transports call
    /// this at the top of `Read::read` and return `WouldBlock` on
    /// `true`; the remote is then naturally stalled by TCP's own
    /// receive-window backpressure.
    pub fn is_paused(&self) -> bool {
        (self.xon_xoff_enabled && self.xoff_paused.load(Ordering::Relaxed))
            || (self.rts_cts_enabled && self.rts_deasserted.load(Ordering::Relaxed))
    }
}

impl Default for FlowControlGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gate_is_enabled_and_unpaused() {
        let g = FlowControlGate::default();
        assert!(g.is_xon_xoff_enabled());
        assert!(g.is_rts_cts_enabled());
        assert!(!g.is_paused());
    }

    #[test]
    fn xoff_pauses_the_gate() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[b'h', b'i', XOFF, b'!']);
        assert!(g.is_paused());
    }

    #[test]
    fn xon_resumes_the_gate() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[XOFF]);
        assert!(g.is_paused());
        g.observe_outbound(&[XON]);
        assert!(!g.is_paused());
    }

    #[test]
    fn xoff_then_xon_in_one_buffer_ends_unpaused() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[XOFF, b'x', XON]);
        assert!(!g.is_paused());
    }

    #[test]
    fn xon_then_xoff_in_one_buffer_ends_paused() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[XON, b'x', XOFF]);
        assert!(g.is_paused());
    }

    #[test]
    fn rts_deassert_pauses_the_gate() {
        let g = FlowControlGate::default();
        g.set_rts(false);
        assert!(g.is_paused());
        g.set_rts(true);
        assert!(!g.is_paused());
    }

    #[test]
    fn either_source_active_pauses() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[XOFF]);
        g.set_rts(true);
        assert!(g.is_paused());

        let g = FlowControlGate::default();
        g.observe_outbound(&[XON]);
        g.set_rts(false);
        assert!(g.is_paused());
    }

    #[test]
    fn both_sources_must_clear_to_resume() {
        let g = FlowControlGate::default();
        g.observe_outbound(&[XOFF]);
        g.set_rts(false);
        assert!(g.is_paused());
        g.observe_outbound(&[XON]);
        assert!(g.is_paused());
        g.set_rts(true);
        assert!(!g.is_paused());
    }

    #[test]
    fn disabled_xon_xoff_ignores_byte_stream() {
        let g = FlowControlGate::with_options(false, true);
        g.observe_outbound(&[XOFF, XOFF, XOFF]);
        assert!(!g.is_paused());
    }

    #[test]
    fn disabled_rts_cts_ignores_rts_line() {
        let g = FlowControlGate::with_options(true, false);
        g.set_rts(false);
        assert!(!g.is_paused());
    }

    #[test]
    fn disable_source_clears_its_pending_state() {
        let mut g = FlowControlGate::default();
        g.observe_outbound(&[XOFF]);
        g.set_rts(false);
        assert!(g.is_paused());
        g.set_xon_xoff_enabled(false);
        // still paused by RTS
        assert!(g.is_paused());
        g.set_rts_cts_enabled(false);
        assert!(!g.is_paused());
    }

    #[test]
    fn non_control_bytes_leave_state_untouched() {
        let g = FlowControlGate::default();
        g.observe_outbound(b"The quick brown fox");
        assert!(!g.is_paused());
    }
}
