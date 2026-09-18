use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tracing_subscriber::fmt::MakeWriter;

pub(crate) const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
pub(crate) const MAX_LOG_FILES: usize = 4;

/// Minimum spacing between two "rotation failed" warnings, so a persistently
/// broken sink cannot flood the log with its own failures.
const ROTATION_WARN_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct DiagnosticMakeWriter {
    inner: Arc<Mutex<RotatingLog>>,
}

impl DiagnosticMakeWriter {
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(RotatingLog::open(directory)?)),
        })
    }

    pub(crate) fn set_directory(&self, directory: &Path) -> io::Result<()> {
        self.lock()?.set_directory(directory)
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        self.lock()?.clear()
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        self.lock()?.flush()
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, RotatingLog>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("diagnostic log lock poisoned"))
    }
}

impl<'a> MakeWriter<'a> for DiagnosticMakeWriter {
    type Writer = BufferedEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferedEventWriter {
            target: self.clone(),
            buffer: Vec::new(),
        }
    }
}

pub(crate) struct BufferedEventWriter {
    target: DiagnosticMakeWriter,
    buffer: Vec<u8>,
}

impl BufferedEventWriter {
    fn commit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let buffer = std::mem::take(&mut self.buffer);
        let mut log = self.target.lock()?;
        log.write_event(&buffer)?;
        let warning = log.take_rotation_warning();
        // Release the lock before emitting: the warning re-enters this
        // writer (and this lock) when the subscriber records it, so holding
        // the guard here would deadlock. ROTATION_WARN_INTERVAL bounds the
        // re-entry depth.
        drop(log);
        if let Some(warning) = warning {
            tracing::warn!(target: "easytier_ios::diagnostics", "{warning}");
        }
        Ok(())
    }
}

impl Write for BufferedEventWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.commit()
    }
}

impl Drop for BufferedEventWriter {
    fn drop(&mut self) {
        let _ = self.commit();
    }
}

struct RotatingLog {
    directory: PathBuf,
    active: Option<File>,
    active_bytes: u64,
    /// Rate-limited rotation failure message, drained by the write path and
    /// emitted as a `warn!` once it no longer holds the log lock.
    pending_rotation_warn: Option<String>,
    last_rotation_warn: Option<Instant>,
}

impl RotatingLog {
    fn open(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let mut log = Self {
            directory: directory.to_owned(),
            active: None,
            active_bytes: 0,
            pending_rotation_warn: None,
            last_rotation_warn: None,
        };
        log.truncate_oversized_files()?;
        log.open_active()?;
        Ok(log)
    }

    fn set_directory(&mut self, directory: &Path) -> io::Result<()> {
        if self.directory == directory && self.active.is_some() {
            return Ok(());
        }
        self.flush()?;
        // Open the new location fully before replacing the current handle,
        // so a failure (e.g. unwritable directory) keeps events flowing into
        // the previous file instead of silently dropping them.
        let replacement = RotatingLog::open(directory)?;
        self.directory = replacement.directory;
        self.active = replacement.active;
        self.active_bytes = replacement.active_bytes;
        Ok(())
    }

    fn active_path(&self) -> PathBuf {
        self.directory.join("easytier.log")
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        self.directory.join(format!("easytier.{index}.log"))
    }

    fn truncate_oversized_files(&self) -> io::Result<()> {
        let paths = std::iter::once(self.active_path())
            .chain((1..MAX_LOG_FILES).map(|index| self.rotated_path(index)));
        for path in paths {
            if path
                .metadata()
                .is_ok_and(|metadata| metadata.len() > MAX_LOG_BYTES)
            {
                OpenOptions::new()
                    .write(true)
                    .open(path)?
                    .set_len(MAX_LOG_BYTES)?;
            }
        }
        Ok(())
    }

    fn open_active(&mut self) -> io::Result<()> {
        let path = self.active_path();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.active_bytes = file.metadata()?.len();
        self.active = Some(file);
        if self.active_bytes >= MAX_LOG_BYTES {
            // Fail-open: with no events to lose here, a failed rotation still
            // leaves the (oversized) active file writable; later events retry.
            if let Err(error) = self.rotate() {
                self.note_rotation_failure(&error);
            }
        }
        Ok(())
    }

    fn append(&mut self, event: &[u8]) -> io::Result<()> {
        if let Some(active) = self.active.as_mut() {
            active.write_all(event)?;
            self.active_bytes += event.len() as u64;
        }
        Ok(())
    }

    fn write_event(&mut self, event: &[u8]) -> io::Result<()> {
        if event.is_empty() {
            return Ok(());
        }
        if self.active_bytes > 0
            && self.active_bytes.saturating_add(event.len() as u64) > MAX_LOG_BYTES
        {
            if let Err(error) = self.rotate() {
                // Rotation failed but `rotate` kept the previous handle open,
                // so append the full event even past MAX_LOG_BYTES instead
                // of dropping it; the oversized file is truncated on the
                // next open.
                self.note_rotation_failure(&error);
                return self.append(event);
            }
        }
        let remaining = MAX_LOG_BYTES.saturating_sub(self.active_bytes) as usize;
        self.append(&event[..event.len().min(remaining)])
    }

    /// All fallible steps run before the active handle is replaced: on any
    /// failure the old file stays open and writable (fail-open), while a
    /// later event retries the rotation.
    fn rotate(&mut self) -> io::Result<()> {
        self.flush()?;

        let oldest = self.rotated_path(MAX_LOG_FILES - 1);
        if oldest.exists() {
            fs::remove_file(oldest)?;
        }
        for index in (1..MAX_LOG_FILES - 1).rev() {
            let source = self.rotated_path(index);
            if source.exists() {
                fs::rename(source, self.rotated_path(index + 1))?;
            }
        }
        let active = self.active_path();
        if active.exists() {
            fs::rename(active, self.rotated_path(1))?;
        }
        let replacement = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.active_path())?;
        self.active = Some(replacement);
        self.active_bytes = 0;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.flush()?;
        let mut failure: Option<io::Error> = None;
        for index in 1..MAX_LOG_FILES {
            match fs::remove_file(self.rotated_path(index)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    failure.get_or_insert(error);
                }
                _ => {}
            }
        }
        // Truncate the active file through a write-mode handle first:
        // append-mode handles cannot truncate on Windows, and truncating
        // before the swap keeps the old handle writable if the reopen below
        // fails.
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.active_path())?;
        let replacement = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.active_path())?;
        self.active = Some(replacement);
        self.active_bytes = 0;
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.active.as_mut() {
            Some(active) => active.flush(),
            None => Ok(()),
        }
    }

    /// Record a rate-limited warning about a swallowed rotation failure; the
    /// write path drains it via `take_rotation_warning` once the log lock has
    /// been released, so the warning never re-enters the lock it was taken
    /// under.
    fn note_rotation_failure(&mut self, error: &io::Error) {
        let now = Instant::now();
        if self
            .last_rotation_warn
            .is_none_or(|at| now.duration_since(at) >= ROTATION_WARN_INTERVAL)
        {
            self.last_rotation_warn = Some(now);
            self.pending_rotation_warn = Some(format!(
                "diagnostic log rotation failed, appending to the active file past the size cap: {error}"
            ));
        }
    }

    fn take_rotation_warning(&mut self) -> Option<String> {
        self.pending_rotation_warn.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("easytier-ios-{name}-{unique}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rotates_without_exceeding_file_limit() {
        let directory = TempDir::new("rotation");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];

        for _ in 0..6 {
            log.write_event(&event).unwrap();
        }
        log.flush().unwrap();

        let files = fs::read_dir(&directory.0)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(files.len(), MAX_LOG_FILES);
        assert!(
            files
                .iter()
                .all(|entry| entry.metadata().unwrap().len() <= MAX_LOG_BYTES)
        );
    }

    #[test]
    fn clear_removes_rotated_content_and_keeps_active_file_writable() {
        let directory = TempDir::new("clear");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];
        log.write_event(&event).unwrap();
        log.write_event(&event).unwrap();

        log.clear().unwrap();
        log.write_event(b"after clear\n").unwrap();
        log.flush().unwrap();

        assert_eq!(fs::read(log.active_path()).unwrap(), b"after clear\n");
        assert!(!log.rotated_path(1).exists());
    }

    #[test]
    fn opening_truncates_oversized_known_files() {
        let directory = TempDir::new("oversized");
        for name in ["easytier.log", "easytier.1.log"] {
            let file = File::create(directory.0.join(name)).unwrap();
            file.set_len(MAX_LOG_BYTES + 1).unwrap();
        }

        let log = RotatingLog::open(&directory.0).unwrap();

        for index in 1..MAX_LOG_FILES {
            let path = log.rotated_path(index);
            if path.exists() {
                assert!(path.metadata().unwrap().len() <= MAX_LOG_BYTES);
            }
        }
        assert!(log.active_path().metadata().unwrap().len() <= MAX_LOG_BYTES);
    }

    #[test]
    fn rotation_failure_keeps_writing_events() {
        let directory = TempDir::new("rotation-failure");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        // A directory in the oldest slot makes `remove_file` fail before any
        // rename runs, deterministically on every platform. (Blocking the
        // final rename instead does not work: the shift loop first moves
        // whatever occupies `easytier.1.log` out of the way.)
        fs::create_dir(log.rotated_path(MAX_LOG_FILES - 1)).unwrap();

        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];
        log.write_event(&event).unwrap();
        // Exceeds the cap, so this triggers the failing rotation.
        log.write_event(&event).unwrap();
        assert!(
            log.take_rotation_warning()
                .is_some_and(|warning| warning.contains("rotation failed")),
            "rotation failure must be reported through the rate-limited warning"
        );
        // Rate limiting: another failing rotation within the interval is not
        // reported again.
        log.write_event(&event).unwrap();
        assert!(log.take_rotation_warning().is_none());

        // Fail-open: the events above and everything after still land in the
        // still-open active file (past the size cap) instead of being
        // silently dropped.
        log.write_event(b"still writable\n").unwrap();
        log.flush().unwrap();
        let content = fs::read(log.active_path()).unwrap();
        assert!(content.ends_with(b"still writable\n"));
        assert!(content.len() > MAX_LOG_BYTES as usize);
    }

    #[test]
    fn set_directory_failure_keeps_writing_events() {
        let directory = TempDir::new("set-directory-failure");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        log.write_event(b"first\n").unwrap();

        // `directory.0/file/sub` lives inside a regular file, so
        // create_dir_all must fail.
        fs::File::create(directory.0.join("file")).unwrap();
        let bad = directory.0.join("file").join("sub");
        log.set_directory(&bad).unwrap_err();

        log.write_event(b"second\n").unwrap();
        log.flush().unwrap();
        assert_eq!(fs::read(log.active_path()).unwrap(), b"first\nsecond\n");
    }
}
