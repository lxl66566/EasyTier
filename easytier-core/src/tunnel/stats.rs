use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use atomic_shim::AtomicU64;

pub struct WindowLatency {
    latency_us_window: Vec<AtomicU32>,
    latency_us_window_index: AtomicU32,
    latency_us_window_size: u32,

    sum: AtomicU32,
    count: AtomicU32,
}

impl std::fmt::Debug for WindowLatency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowLatency")
            .field("count", &self.count)
            .field("window_size", &self.latency_us_window_size)
            .field("window_latency", &self.get_latency_us::<u32>())
            .finish()
    }
}

impl WindowLatency {
    pub fn new(window_size: u32) -> Self {
        Self {
            latency_us_window: (0..window_size).map(|_| AtomicU32::new(0)).collect(),
            latency_us_window_index: AtomicU32::new(0),
            latency_us_window_size: window_size,

            sum: AtomicU32::new(0),
            count: AtomicU32::new(0),
        }
    }

    pub fn record_latency(&self, latency_us: u32) {
        let index = self.latency_us_window_index.fetch_add(1, Relaxed);
        if self.count.load(Relaxed) < self.latency_us_window_size {
            self.count.fetch_add(1, Relaxed);
        }

        let index = index % self.latency_us_window_size;
        let old_lat = self.latency_us_window[index as usize].swap(latency_us, Relaxed);

        if old_lat < latency_us {
            self.sum.fetch_add(latency_us - old_lat, Relaxed);
        } else {
            self.sum.fetch_sub(old_lat - latency_us, Relaxed);
        }
    }

    pub fn get_latency_us<T: From<u32> + std::ops::Div<Output = T>>(&self) -> T {
        let count = self.count.load(Relaxed);
        let sum = self.sum.load(Relaxed);
        if count == 0 {
            0.into()
        } else {
            (T::from(sum)) / T::from(count)
        }
    }
}

/// Per-tunnel byte/packet counters, safe for concurrent use from multiple
/// threads (tunnel rx/tx tasks record, ping task reads through a shared
/// `Arc`). All operations are atomic with `Relaxed` ordering, which suffices
/// for pure counting.
#[derive(Debug)]
pub struct Throughput {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
}

impl Clone for Throughput {
    fn clone(&self) -> Self {
        Self {
            tx_bytes: AtomicU64::new(self.tx_bytes.load(Relaxed)),
            rx_bytes: AtomicU64::new(self.rx_bytes.load(Relaxed)),
            tx_packets: AtomicU64::new(self.tx_packets.load(Relaxed)),
            rx_packets: AtomicU64::new(self.rx_packets.load(Relaxed)),
        }
    }
}

impl Default for Throughput {
    fn default() -> Self {
        Self::new()
    }
}

impl Throughput {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
        }
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Relaxed)
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets.load(Relaxed)
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets.load(Relaxed)
    }

    pub fn record_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Relaxed);
        self.tx_packets.fetch_add(1, Relaxed);
    }

    pub fn record_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Relaxed);
        self.rx_packets.fetch_add(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn concurrent_record_keeps_counters_monotonic_and_exact() {
        const WRITERS: usize = 4;
        const ROUNDS: u64 = 10_000;

        let throughput = Arc::new(Throughput::new());
        let stop = Arc::new(AtomicBool::new(false));

        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let throughput = throughput.clone();
                std::thread::spawn(move || {
                    for _ in 0..ROUNDS {
                        throughput.record_tx_bytes(7);
                        throughput.record_rx_bytes(3);
                    }
                })
            })
            .collect();

        let reader = {
            let throughput = throughput.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let (mut last_tx, mut last_rx) = (0, 0);
                while !stop.load(Ordering::Relaxed) {
                    let tx = throughput.tx_bytes();
                    let rx = throughput.rx_bytes();
                    assert!(tx >= last_tx, "tx_bytes went backwards: {tx} < {last_tx}");
                    assert!(rx >= last_rx, "rx_bytes went backwards: {rx} < {last_rx}");
                    last_tx = tx;
                    last_rx = rx;
                }
            })
        };

        for writer in writers {
            writer.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert_eq!(throughput.tx_bytes(), (WRITERS as u64) * ROUNDS * 7);
        assert_eq!(throughput.rx_bytes(), (WRITERS as u64) * ROUNDS * 3);
        assert_eq!(throughput.tx_packets(), (WRITERS as u64) * ROUNDS);
        assert_eq!(throughput.rx_packets(), (WRITERS as u64) * ROUNDS);
    }

    #[test]
    fn clone_snapshots_current_values() {
        let throughput = Throughput::new();
        throughput.record_tx_bytes(42);
        throughput.record_rx_bytes(17);
        let snapshot = throughput.clone();
        throughput.record_tx_bytes(100);
        assert_eq!(snapshot.tx_bytes(), 42);
        assert_eq!(snapshot.rx_bytes(), 17);
        assert_eq!(snapshot.tx_packets(), 1);
        assert_eq!(snapshot.rx_packets(), 1);
        assert_eq!(throughput.tx_bytes(), 142);
        assert_eq!(throughput.tx_packets(), 2);
    }
}
