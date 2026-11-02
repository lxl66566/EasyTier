//! Shared sliding replay window for packet sequence numbers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic-ish wall clock in milliseconds, shared by replay bookkeeping.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Sliding-window replay filter over a monotonically increasing sequence.
///
/// Accepts any sequence that advances the maximum, or that falls behind it
/// by less than [`Self::WINDOW`] positions without having been seen before.
/// This tolerates reordering (UDP, multi-path relaying) up to `WINDOW`
/// packets while rejecting duplicates and anything older than the window.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ReplayWindow256 {
    max_seq: u64,
    bitmap: [u8; 32],
    valid: bool,
}

impl ReplayWindow256 {
    pub(crate) const WINDOW: u64 = 256;

    pub(crate) fn clear(&mut self) {
        self.max_seq = 0;
        self.bitmap.fill(0);
        self.valid = false;
    }

    /// Highest sequence recorded so far (for assertions and diagnostics).
    #[cfg(test)]
    pub(crate) fn max_seq(&self) -> u64 {
        self.max_seq
    }

    fn test_bit(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        (self.bitmap[byte] >> bit) & 1 == 1
    }

    fn set_bit(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] |= 1u8 << bit;
    }

    fn shift_right(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        let total_bits = 256usize;
        if shift >= total_bits {
            self.bitmap.fill(0);
            return;
        }

        let byte_shift = shift / 8;
        let bit_shift = shift % 8;

        if byte_shift > 0 {
            for i in (0..self.bitmap.len()).rev() {
                self.bitmap[i] = if i >= byte_shift {
                    self.bitmap[i - byte_shift]
                } else {
                    0
                };
            }
        }

        if bit_shift > 0 {
            let mut carry = 0u8;
            for b in self.bitmap.iter_mut() {
                let new_carry = *b >> (8 - bit_shift);
                *b = (*b << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    /// Check-and-set: returns `false` if `seq` is a duplicate or too old.
    pub(crate) fn accept(&mut self, seq: u64) -> bool {
        if !self.valid {
            self.valid = true;
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }

        if seq > self.max_seq {
            let shift = (seq - self.max_seq) as usize;
            self.shift_right(shift);
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        if delta >= Self::WINDOW as usize {
            return false;
        }
        if self.test_bit(delta) {
            return false;
        }
        self.set_bit(delta);
        true
    }

    /// Read-only variant of [`Self::accept`] for pre-checks.
    pub(crate) fn can_accept(&self, seq: u64) -> bool {
        if !self.valid || seq > self.max_seq {
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        delta < Self::WINDOW as usize && !self.test_bit(delta)
    }
}
