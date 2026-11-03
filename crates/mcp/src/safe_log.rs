//! Privacy-by-construction operational logs. Even RUST_LOG=trace cannot emit
//! screen text, typed input, provider responses, credentials or URL queries.
//! A stable callsite, severity and allowlisted counters remain diagnosable.

use std::fmt;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Used by desktop, MCP and embedded daemons. No unsafe diagnostic mode.
pub struct PrivacyFormatter;

#[derive(Default)]
struct SafeFields(String);

/// Counter names are an allowlist, not a denylist of guessed secret names.
fn counter(name: &str) -> bool {
    matches!(
        name,
        "duration_ms"
            | "elapsed_ms"
            | "count"
            | "status"
            | "pid"
            | "port"
            | "attempts"
            | "bytes"
            | "rows"
            | "retry"
            | "ok"
    )
}

impl Visit for SafeFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if counter(field.name()) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        if counter(field.name()) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        if counter(field.name()) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        let operation = field.name() == "operation"
            && matches!(
                value,
                "create_agent"
                    | "revoke"
                    | "revoke_all"
                    | "revoke_devices"
                    | "takeover"
                    | "remote_enable"
                    | "remote_disable"
            );
        let opaque = matches!(field.name(), "principal" | "reason_digest")
            && value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if operation || opaque {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }
    fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {
        // The formatted message and %error fields may contain arbitrary UI or
        // remote response data. Never invoke their formatting implementations.
    }
}

impl<S, N> FormatEvent<S, N> for PrivacyFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut fields = SafeFields::default();
        event.record(&mut fields);
        writeln!(
            writer,
            "{} {} {}:{}{}",
            now,
            metadata.level(),
            metadata.file().unwrap_or(metadata.target()),
            metadata.line().unwrap_or(0),
            fields.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn raw_messages_spans_credentials_and_screen_fields_never_reach_logs() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .event_format(PrivacyFormatter)
            .with_writer(move || Sink(writer.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("fixture", password = "fixture-span-password");
            let _entered = span.enter();
            tracing::error!(token="fixture-token",body="fixture-screen",error=?"fixture-provider-error",
                url="https://fixture.invalid?secret=fixture-url",duration_ms=10u64,
                operation="revoke","fixture-message-with-input");
        });
        let text = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        for secret in [
            "fixture-span-password",
            "fixture-token",
            "fixture-screen",
            "fixture-provider-error",
            "fixture-url",
            "fixture-message-with-input",
        ] {
            assert!(!text.contains(secret), "private data reached logs");
        }
        assert!(text.contains("ERROR"));
        assert!(text.contains("duration_ms=10"));
        assert!(text.contains("operation=revoke"));
    }
}
