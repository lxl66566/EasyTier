use zerocopy::{AsBytes as _, FromBytes as _};

use super::{COMPRESSOR_TAIL_SIZE, CompressorAlgo, CompressorTail, ZCPacket};

mod zstd;

type Error = anyhow::Error;

#[async_trait::async_trait]
pub trait Compressor {
    async fn compress(
        &self,
        packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
    ) -> Result<(), Error>;
    async fn decompress(&self, packet: &mut ZCPacket) -> Result<(), Error>;
}

pub struct DefaultCompressor {}

impl Default for DefaultCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCompressor {
    pub fn new() -> Self {
        DefaultCompressor {}
    }

    pub async fn compress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            CompressorAlgo::ZstdDefault => zstd::compress(data, compress_algo),
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    pub async fn decompress_raw(
        &self,
        data: &[u8],
        expected_len: usize,
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            CompressorAlgo::ZstdDefault => zstd::decompress(data, expected_len, compress_algo),
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }
}

#[async_trait::async_trait]
impl Compressor for DefaultCompressor {
    async fn compress(
        &self,
        zc_packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
    ) -> Result<(), Error> {
        if matches!(compress_algo, CompressorAlgo::None) {
            return Ok(());
        }

        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_compressed() {
            return Ok(());
        }
        let orig_len = pm_header.len.get() as usize;

        compress_algo.ensure_available()?;

        let payload_offset = zc_packet.payload_offset();
        let payload_len = zc_packet.payload().len();

        // Reserve the worst-case compressed size at the buffer tail and
        // compress the payload directly into it: no intermediate Vec and no
        // reallocation after compression. compress_bound guarantees the
        // reserved region always fits the compressed output.
        let tail = CompressorTail::new(compress_algo);
        let bound = zstd::compress_bound(payload_len);
        zc_packet.mut_inner().resize(
            payload_offset + payload_len + bound + COMPRESSOR_TAIL_SIZE,
            0,
        );

        let compress_result = {
            let region = &mut zc_packet.mut_inner()[payload_offset..];
            let (payload, dst) = region.split_at_mut(payload_len);
            zstd::compress_into(payload, dst, compress_algo)
        };
        let compressed_len = match compress_result {
            Ok(compressed_len) => compressed_len,
            Err(error) => {
                zc_packet.mut_inner().truncate(payload_offset + payload_len);
                return Err(error);
            }
        };

        if compressed_len + COMPRESSOR_TAIL_SIZE > orig_len {
            // Compressed data is larger than original data, don't compress
            zc_packet.mut_inner().truncate(payload_offset + payload_len);
            return Ok(());
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(true);

        // Move the compressed bytes from the tail region to the payload
        // position, then drop the leftover scratch space.
        let inner = zc_packet.mut_inner();
        inner.copy_within(
            payload_offset + payload_len..payload_offset + payload_len + compressed_len,
            payload_offset,
        );
        inner.truncate(payload_offset + compressed_len);
        inner.extend_from_slice(tail.as_bytes());

        Ok(())
    }

    async fn decompress(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_compressed() {
            return Ok(());
        }
        let expected_len = pm_header.len.get() as usize;

        let payload_len = zc_packet.payload().len();
        if payload_len < COMPRESSOR_TAIL_SIZE {
            return Err(anyhow::anyhow!("Packet too short: {}", payload_len));
        }

        let text_len = payload_len - COMPRESSOR_TAIL_SIZE;

        let tail = CompressorTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let algo = tail
            .get_algo()
            .ok_or(anyhow::anyhow!("Unknown algo: {:?}", tail))?;

        // The peer manager header advertises the exact decompressed length,
        // so decompression can allocate once instead of guessing.
        let buf = self
            .decompress_raw(&zc_packet.payload()[..text_len], expected_len, algo)
            .await?;

        if buf.len() != pm_header.len.get() as usize {
            anyhow::bail!(
                "Decompressed length mismatch: decompressed len {} != pm header len {}",
                buf.len(),
                pm_header.len.get()
            );
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(false);

        let payload_offset = zc_packet.payload_offset();
        zc_packet.mut_inner().truncate(payload_offset);
        zc_packet.mut_inner().extend_from_slice(&buf);

        Ok(())
    }
}

pub(super) fn zstd_available() -> bool {
    zstd::AVAILABLE
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[cfg(feature = "zstd")]
    #[tokio::test]
    async fn test_compress() {
        let text = b"12345670000000000000000000";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        println!(
            "Uncompressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );

        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        println!(
            "Compressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );
        assert!(packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[cfg(feature = "zstd")]
    #[tokio::test]
    async fn test_short_text_compress() {
        let text = b"1234";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        // short text can't be compressed
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[cfg(feature = "zstd")]
    #[tokio::test]
    async fn test_high_ratio_compress_roundtrip() {
        // Highly repetitive payload compresses far below the original size;
        // with the old length guessing this needed every retry attempt.
        let text = vec![0xab_u8; 64 * 1024];
        let mut packet = ZCPacket::new_with_payload(&text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        assert!(packet.peer_manager_header().unwrap().is_compressed());
        assert!(packet.payload().len() < text.len());

        // The advertised pm header length lets decompression succeed in a
        // single exact-size attempt.
        let expected_len = packet.peer_manager_header().unwrap().len.get() as usize;
        let compressed = &packet.payload()[..packet.payload().len() - COMPRESSOR_TAIL_SIZE];
        let decompressed =
            zstd::decompress(compressed, expected_len, CompressorAlgo::ZstdDefault).unwrap();
        assert_eq!(decompressed.len(), expected_len);
        assert_eq!(decompressed, text);

        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), &text[..]);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[cfg(feature = "zstd")]
    #[tokio::test]
    async fn test_decompress_forged_pm_header_len() {
        let text = vec![0x77_u8; 8 * 1024];
        let mut packet = ZCPacket::new_with_payload(&text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        assert!(packet.peer_manager_header().unwrap().is_compressed());

        // A forged length that is too small makes the exact-size attempt fail
        // on capacity and fall back to guessing; the mismatch check still
        // rejects the packet without mutating it.
        packet.mut_peer_manager_header().unwrap().len.set(1);
        let err = compressor.decompress(&mut packet).await.unwrap_err();
        assert!(err.to_string().contains("Decompressed length mismatch"));

        // A forged oversized length must not attempt a huge allocation; it is
        // ignored in favor of bounded guessing and rejected by the same
        // mismatch check.
        packet.mut_peer_manager_header().unwrap().len.set(u32::MAX);
        let err = compressor.decompress(&mut packet).await.unwrap_err();
        assert!(err.to_string().contains("Decompressed length mismatch"));

        // Restoring the correct length recovers the original payload.
        packet
            .mut_peer_manager_header()
            .unwrap()
            .len
            .set(text.len() as u32);
        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.payload(), &text[..]);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[cfg(not(feature = "zstd"))]
    #[tokio::test]
    async fn unavailable_zstd_returns_an_explicit_error() {
        let error = DefaultCompressor::new()
            .compress_raw(b"payload", CompressorAlgo::ZstdDefault)
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "compression algorithm is unavailable in this build: ZstdDefault"
        );
    }
}
