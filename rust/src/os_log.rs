use std::{
    ffi::{CStr, CString},
    sync::{Arc, Mutex},
};

use tracing::Level;

use crate::ffi::{
    os_log_create, os_log_t, os_log_type_t, os_log_type_t_OS_LOG_TYPE_DEBUG,
    os_log_type_t_OS_LOG_TYPE_ERROR, os_log_type_t_OS_LOG_TYPE_INFO, os_log_with_type_rs,
    os_release, os_signpost_id_t, os_signpost_interval_begin_rs, os_signpost_interval_end_rs,
};

mod layer;
mod signpost;
mod writer;

pub(crate) use layer::layers;

#[derive(Debug)]
pub(crate) struct OsLog(os_log_t);
unsafe impl Send for OsLog {}

impl OsLog {
    fn new(subsystem: &str, category: &str) -> Arc<Mutex<Self>> {
        let subsystem = CString::new(subsystem).expect("has no internal nul bytes");
        let category = CString::new(category).expect("has no internal nul bytes");
        Arc::new(Mutex::new(Self(unsafe {
            os_log_create(subsystem.as_ptr(), category.as_ptr())
        })))
    }

    fn log_with_type(&mut self, log_type: LogType, message: &CStr) {
        unsafe { os_log_with_type_rs(self.0, log_type.as_raw(), message.as_ptr()) };
    }

    fn signpost_interval_begin(&mut self, interval_id: os_signpost_id_t, label: &CStr) {
        unsafe { os_signpost_interval_begin_rs(self.0, interval_id, label.as_ptr()) };
    }

    fn signpost_interval_end(&mut self, interval_id: os_signpost_id_t, label: &CStr) {
        unsafe { os_signpost_interval_end_rs(self.0, interval_id, label.as_ptr()) };
    }
}

impl Drop for OsLog {
    fn drop(&mut self) {
        unsafe { os_release(self.0.cast()) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum LogType {
    Debug = os_log_type_t_OS_LOG_TYPE_DEBUG,
    Info = os_log_type_t_OS_LOG_TYPE_INFO,
    Error = os_log_type_t_OS_LOG_TYPE_ERROR,
}

impl LogType {
    fn as_raw(self) -> os_log_type_t {
        self as os_log_type_t
    }
}

impl From<Level> for LogType {
    fn from(level: Level) -> Self {
        match level {
            Level::TRACE | Level::DEBUG => LogType::Debug,
            Level::INFO => LogType::Info,
            Level::WARN | Level::ERROR => LogType::Error,
        }
    }
}

impl From<&Level> for LogType {
    fn from(level: &Level) -> Self {
        Self::from(*level)
    }
}
