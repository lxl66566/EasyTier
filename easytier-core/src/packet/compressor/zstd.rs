#[cfg(feature = "zstd")]
use std::cell::RefCell;

#[cfg(feature = "zstd")]
use anyhow::Context as _;
#[cfg(feature = "zstd")]
use dashmap::DashMap;
#[cfg(feature = "zstd")]
use zstd::bulk;

use super::CompressorAlgo;

#[cfg(feature = "zstd")]
pub(super) const AVAILABLE: bool = true;
#[cfg(not(feature = "zstd"))]
pub(super) const AVAILABLE: bool = false;

#[cfg(feature = "zstd")]
thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> =
        RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> =
        RefCell::new(DashMap::new());
}

/// Worst-case output size of a single-pass compression of `src_len` bytes.
/// zstd guarantees a destination of this size is always sufficient, so a
/// caller that reserves `compress_bound` bytes never needs to retry.
#[cfg(feature = "zstd")]
pub(super) fn compress_bound(src_len: usize) -> usize {
    zstd::zstd_safe::compress_bound(src_len)
}

#[cfg(not(feature = "zstd"))]
pub(super) fn compress_bound(_src_len: usize) -> usize {
    // Callers check algo availability before reserving scratch space; the
    // unavailable compress_into below errors out anyway.
    0
}

/// Compress `data` directly into `dst` and return the compressed length.
/// `dst.len()` must be at least `compress_bound(data.len())`.
#[cfg(feature = "zstd")]
pub(super) fn compress_into(
    data: &[u8],
    dst: &mut [u8],
    compress_algo: CompressorAlgo,
) -> anyhow::Result<usize> {
    CTX_MAP.with(|map_cell| {
        let map = map_cell.borrow();
        let mut ctx_entry = map.entry(compress_algo).or_default();
        ctx_entry.compress_to_buffer(data, dst).with_context(|| {
            format!(
                "Failed to compress data with algorithm: {:?}",
                compress_algo
            )
        })
    })
}

#[cfg(not(feature = "zstd"))]
pub(super) fn compress_into(
    _data: &[u8],
    _dst: &mut [u8],
    compress_algo: CompressorAlgo,
) -> anyhow::Result<usize> {
    Err(unavailable(compress_algo))
}

#[cfg(feature = "zstd")]
pub(super) fn compress(data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    CTX_MAP.with(|map_cell| {
        let map = map_cell.borrow();
        let mut ctx_entry = map.entry(compress_algo).or_default();
        ctx_entry.compress(data).with_context(|| {
            format!(
                "Failed to compress data with algorithm: {:?}",
                compress_algo
            )
        })
    })
}

#[cfg(not(feature = "zstd"))]
pub(super) fn compress(_data: &[u8], compress_algo: CompressorAlgo) -> anyhow::Result<Vec<u8>> {
    Err(unavailable(compress_algo))
}

/// Output buffer length tried by the guessing attempt `attempt` (1-based).
/// Mirrors the legacy fallback: grow geometrically, force at least 64 KiB on
/// the last attempt.
#[cfg(feature = "zstd")]
fn guess_len(data_len: usize, attempt: u32) -> usize {
    let len = data_len * 2usize.pow(attempt);
    if attempt == 5 && len < 64 * 1024 {
        64 * 1024
    } else {
        len
    }
}

/// zstd maps error codes to io::Error carrying the zstd message; the
/// dstSizeTooSmall code reports "Destination buffer is too small".
#[cfg(feature = "zstd")]
fn is_dst_size_too_small(error: &std::io::Error) -> bool {
    error.to_string().contains("buffer is too small")
}

/// Decompress `data` into a freshly allocated Vec.
///
/// `expected_len` is the decompressed length advertised by the peer manager
/// header; when it is plausible it is used for a single exact-size allocation
/// and one decompression attempt. The geometric guessing loop is kept only as
/// a fallback for packets whose length field is forged or absent (0).
#[cfg(feature = "zstd")]
pub(super) fn decompress(
    data: &[u8],
    expected_len: usize,
    compress_algo: CompressorAlgo,
) -> anyhow::Result<Vec<u8>> {
    DCTX_MAP.with(|map_cell| {
        let map = map_cell.borrow();
        let mut ctx_entry = map.entry(compress_algo).or_default();

        // Trust the advertised length only up to the size the guessing loop
        // would try anyway, so a forged huge length cannot cause an oversized
        // allocation; larger values simply fall back to guessing.
        if expected_len > 0 && expected_len <= guess_len(data.len(), 5) {
            let mut buf = Vec::with_capacity(expected_len);
            match ctx_entry.decompress_to_buffer(data, &mut buf) {
                Ok(_) => return Ok(buf),
                Err(error) if is_dst_size_too_small(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }

        for i in 1..=5 {
            let len = guess_len(data.len(), i);
            match ctx_entry.decompress(data, len) {
                Ok(buf) => return Ok(buf),
                Err(error) if is_dst_size_too_small(&error) => continue,
                Err(error) => return Err(error.into()),
            }
        }

        Err(anyhow::anyhow!(
            "Failed to decompress data after multiple attempts with algorithm: {:?}",
            compress_algo
        ))
    })
}

#[cfg(not(feature = "zstd"))]
pub(super) fn decompress(
    _data: &[u8],
    _expected_len: usize,
    compress_algo: CompressorAlgo,
) -> anyhow::Result<Vec<u8>> {
    Err(unavailable(compress_algo))
}

#[cfg(not(feature = "zstd"))]
fn unavailable(compress_algo: CompressorAlgo) -> anyhow::Error {
    super::super::CompressionUnavailableError(compress_algo).into()
}
