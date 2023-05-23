use std::{
    ffi::CStr,
    io::{self, Write},
    sync::{Arc, Mutex, MutexGuard},
};

use once_cell::sync::Lazy;
use sharded_slab::{pool::RefMut, Pool};
use tracing_subscriber::fmt::MakeWriter;

use super::{LogType, OsLog};

static BUFFER_POOL: Lazy<Pool<Vec<u8>>> = Lazy::new(|| Pool::new());

/// A [`MakeWriter`] suitable for writing to the Apple OS logging system.
#[derive(Debug)]
pub struct AppleOsLogMakeWriter {
    log: Arc<Mutex<OsLog>>,
}

impl AppleOsLogMakeWriter {
    pub(crate) fn new(log: Arc<Mutex<OsLog>>) -> Self {
        Self { log }
    }
}

impl<'a> MakeWriter<'a> for AppleOsLogMakeWriter {
    type Writer = AppleOsLogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Self::Writer {
            log: self.log.lock().unwrap(),
            log_type: LogType::Info,
            message: Buffer::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        Self::Writer {
            log: self.log.lock().unwrap(),
            log_type: meta.level().into(),
            message: Buffer::new(),
        }
    }
}

/// A writer for the Apple OS logging system.
pub struct AppleOsLogWriter<'a> {
    log: MutexGuard<'a, OsLog>,
    log_type: LogType,
    message: Buffer,
}

impl<'a> Drop for AppleOsLogWriter<'a> {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

impl<'a> io::Write for AppleOsLogWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.message.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(message) = self.message.as_c_str() {
            self.log.log_with_type(self.log_type, message);
        }

        Ok(())
    }
}

struct Buffer(RefMut<'static, Vec<u8>>);

impl Buffer {
    fn new() -> Self {
        Self(BUFFER_POOL.create().unwrap())
    }

    fn write(&mut self, buf: &[u8]) {
        self.0.extend_from_slice(buf);
    }

    fn as_c_str(&mut self) -> Option<&CStr> {
        if self.0.last() != Some(&0) {
            self.0.push(0);
        }

        CStr::from_bytes_with_nul(&self.0).ok()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        BUFFER_POOL.clear(self.0.key());
    }
}
