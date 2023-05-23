use std::{
    ffi::CString,
    sync::{Arc, Mutex},
};

use tracing::{span, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

use crate::ffi::{os_signpost_id_generate, os_signpost_id_t};

use super::OsLog;

struct Signpost {
    id: os_signpost_id_t,
    label: CString,
}

impl Signpost {
    fn new(log: &mut OsLog, label: CString) -> Self {
        Self {
            id: unsafe { os_signpost_id_generate(log.0) },
            label,
        }
    }

    fn begin(&self, log: &mut OsLog) {
        log.signpost_interval_begin(self.id, &self.label);
    }

    fn end(&self, log: &mut OsLog) {
        log.signpost_interval_end(self.id, &self.label);
    }
}

fn with_signpost<S, F>(id: &span::Id, ctx: Context<S>, f: F)
where
    S: Subscriber,
    for<'lookup> S: LookupSpan<'lookup>,
    F: FnOnce(&Signpost),
{
    let span = ctx.span(id).expect("span should be valid");
    let extensions = span.extensions();
    let signpost = extensions
        .get::<Signpost>()
        .expect("span has not been closed yet");
    f(signpost);
}

pub(crate) struct OsSignpost {
    log: Arc<Mutex<OsLog>>,
}

impl OsSignpost {
    pub(crate) fn new(log: Arc<Mutex<OsLog>>) -> Self {
        Self { log }
    }
}

impl<S: Subscriber> Layer<S> for OsSignpost
where
    for<'lookup> S: LookupSpan<'lookup>,
{
    fn on_new_span(&self, _attrs: &span::Attributes, id: &span::Id, ctx: Context<S>) {
        let span = ctx.span(id).expect("span has just been created");
        let mut extensions = span.extensions_mut();
        if extensions.get_mut::<Signpost>().is_none() {
            let metadata = span.metadata();
            let function_name = [metadata.target(), metadata.name()].join("::");
            let label = CString::new(function_name).expect("name should not contain nul bytes");

            let mut log = self.log.lock().unwrap();
            let signpost = Signpost::new(&mut log, label);
            extensions.insert(signpost);
        }
    }

    fn on_enter(&self, id: &span::Id, ctx: Context<S>) {
        with_signpost(id, ctx, |signpost| {
            signpost.begin(&mut self.log.lock().unwrap());
        })
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<S>) {
        with_signpost(id, ctx, |signpost| {
            signpost.end(&mut self.log.lock().unwrap());
        })
    }

    fn on_close(&self, id: span::Id, ctx: Context<S>) {
        let span = ctx.span(&id).expect("span should be valid");
        let mut extensions = span.extensions_mut();
        extensions
            .remove::<Signpost>()
            .expect("span has not been closed before");
    }
}
