//! Time formatting: local timestamps, relative times and durations.
//!
//! All times come from the database as Unix milliseconds (`i64`).
//! The pure functions (`relative_time`, `format_duration`) take the
//! "current time" as a parameter and are therefore testable without a clock.
//! The module is also used by the TUI.

use chrono::{DateTime, Local};

const SECOND: i64 = 1_000;
const MINUTE: i64 = 60 * SECOND;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;
const MONTH: i64 = 30 * DAY;
const YEAR: i64 = 365 * DAY;

/// Formats a Unix-millisecond timestamp in local time
/// (`2026-10-01 14:30`).
///
/// Invalid timestamps (outside the representable range) yield `"?"`.
pub fn format_local(ts_ms: i64) -> String {
    // `DateTime::from_timestamp_millis` returns an `Option` (None for
    // impossible values). `map_or_else` evaluates it without a `match`.
    DateTime::from_timestamp_millis(ts_ms).map_or_else(
        || "?".to_owned(),
        |utc| {
            // `with_timezone(&Local)` converts UTC to the system's local time.
            utc.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        },
    )
}

/// Running day number (local time zone) of a timestamp.
///
/// Two timestamps on the same calendar day yield the same number, consecutive
/// days differ by 1. Intended for per-day count charts.
/// Invalid timestamps yield `None`.
pub fn local_day_number(ts_ms: i64) -> Option<i32> {
    use chrono::Datelike;
    DateTime::from_timestamp_millis(ts_ms)
        .map(|utc| utc.with_timezone(&Local).date_naive().num_days_from_ce())
}

/// Picks singular or plural: `unit(1, "day", "days")` -> `"1 day ago"`.
fn unit(n: i64, singular: &str, plural: &str) -> String {
    format!("{n} {} ago", if n == 1 { singular } else { plural })
}

/// Relative time ("3 days ago", "just now") for `ts_ms` as seen from `now_ms`.
///
/// Timestamps in the future (clock jump) are treated like "just now".
pub fn relative_time(ts_ms: i64, now_ms: i64) -> String {
    // `saturating_sub` doesn't overflow on extreme values but stays at the limit.
    let diff = now_ms.saturating_sub(ts_ms);
    if diff < MINUTE {
        "just now".to_owned()
    } else if diff < HOUR {
        unit(diff / MINUTE, "min", "min")
    } else if diff < DAY {
        unit(diff / HOUR, "h", "h")
    } else if diff < MONTH {
        unit(diff / DAY, "day", "days")
    } else if diff < YEAR {
        unit(diff / MONTH, "month", "months")
    } else {
        unit(diff / YEAR, "year", "years")
    }
}

/// Compact duration: `<1 s`, `42 s`, `42 min`, `2 h 5 min`.
pub fn format_duration(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < SECOND {
        "<1 s".to_owned()
    } else if ms < MINUTE {
        format!("{} s", ms / SECOND)
    } else if ms < HOUR {
        format!("{} min", ms / MINUTE)
    } else {
        format!("{} h {} min", ms / HOUR, (ms % HOUR) / MINUTE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn just_now() {
        assert_eq!(relative_time(NOW, NOW), "just now");
        assert_eq!(relative_time(NOW - 59 * SECOND, NOW), "just now");
    }

    #[test]
    fn future_is_just_now() {
        assert_eq!(relative_time(NOW + HOUR, NOW), "just now");
    }

    #[test]
    fn singular_and_plural() {
        assert_eq!(relative_time(NOW - MINUTE, NOW), "1 min ago");
        assert_eq!(relative_time(NOW - 5 * MINUTE, NOW), "5 min ago");
        assert_eq!(relative_time(NOW - HOUR, NOW), "1 h ago");
        assert_eq!(relative_time(NOW - 23 * HOUR, NOW), "23 h ago");
        assert_eq!(relative_time(NOW - DAY, NOW), "1 day ago");
        assert_eq!(relative_time(NOW - 3 * DAY, NOW), "3 days ago");
        assert_eq!(relative_time(NOW - 29 * DAY, NOW), "29 days ago");
        assert_eq!(relative_time(NOW - 30 * DAY, NOW), "1 month ago");
        assert_eq!(relative_time(NOW - 90 * DAY, NOW), "3 months ago");
        assert_eq!(relative_time(NOW - 365 * DAY, NOW), "1 year ago");
        assert_eq!(relative_time(NOW - 800 * DAY, NOW), "2 years ago");
    }

    #[test]
    fn extreme_values_do_not_panic() {
        let _ = relative_time(i64::MIN, i64::MAX);
        let _ = format_local(i64::MAX);
    }

    #[test]
    fn day_numbers_count_calendar_days() {
        let a = local_day_number(NOW).unwrap();
        // 36 h later is guaranteed to be a different calendar day, but at most 2 days later.
        let b = local_day_number(NOW + 36 * HOUR).unwrap();
        assert!((1..=2).contains(&(b - a)));
        assert_eq!(local_day_number(NOW), local_day_number(NOW + 1));
        assert_eq!(local_day_number(i64::MAX), None);
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(-5), "<1 s");
        assert_eq!(format_duration(999), "<1 s");
        assert_eq!(format_duration(42 * SECOND), "42 s");
        assert_eq!(format_duration(42 * MINUTE + 5 * SECOND), "42 min");
        assert_eq!(format_duration(2 * HOUR + 5 * MINUTE), "2 h 5 min");
    }

    #[test]
    fn local_format_has_expected_shape() {
        let s = format_local(NOW);
        // "YYYY-MM-DD HH:MM" = 16 characters, independent of the time zone.
        assert_eq!(s.len(), 16);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], " ");
    }
}
