use tracing::Subscriber;
use tracing_subscriber::{
    fmt::{
        self,
        format::{self, Format},
    },
    registry::LookupSpan,
};

use super::{signpost::OsSignpost, writer::AppleOsLogMakeWriter, OsLog};

pub(crate) type Layer<S, N = format::DefaultFields, E = format::Full> =
    fmt::Layer<S, N, format::Format<E, ()>, AppleOsLogMakeWriter>;

pub(crate) fn layers<S>(subsystem: &str, category: &str) -> (Layer<S>, OsSignpost)
where
    S: Subscriber,
    for<'a> S: LookupSpan<'a>,
{
    let log = OsLog::new(subsystem, category);
    (
        fmt::Layer::new()
            .event_format(
                Format::default()
                    .with_ansi(false)
                    .with_level(false)
                    .without_time(),
            )
            .with_writer(AppleOsLogMakeWriter::new(log.clone())),
        OsSignpost::new(log),
    )
}
