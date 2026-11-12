//! Small helpers for the human-readable `show` output.

use std::collections::BTreeMap;

/// 1234567 -> "1,234,567"
pub fn commas(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// "1 event", "1,234 events"
pub fn plural(count: u64, noun: &str) -> String {
    format!(
        "{} {noun}{}",
        commas(count),
        if count == 1 { "" } else { "s" }
    )
}

/// A counter's entries, most frequent first, ties broken by name.
pub fn ranked(counter: &BTreeMap<String, u64>) -> Vec<(&str, u64)> {
    let mut entries: Vec<(&str, u64)> = counter.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    entries
}

/// "a (12), b (3) +4 more" for the most common entries of a counter.
pub fn top(counter: &BTreeMap<String, u64>, limit: usize) -> String {
    let entries = ranked(counter);
    let shown: Vec<String> = entries
        .iter()
        .take(limit)
        .map(|(name, count)| format!("{name} ({})", commas(*count)))
        .collect();
    let mut out = shown.join(", ");
    if entries.len() > limit {
        out.push_str(&format!(
            " +{} more",
            commas((entries.len() - limit) as u64)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_grouped_in_thousands() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(1234567), "1,234,567");
        assert_eq!(plural(1, "peer"), "1 peer");
        assert_eq!(plural(2500, "event"), "2,500 events");
    }

    #[test]
    fn top_ranks_by_count_then_name() {
        let counter = BTreeMap::from([
            ("b".to_string(), 2),
            ("a".to_string(), 2),
            ("c".to_string(), 9),
            ("d".to_string(), 1),
        ]);
        assert_eq!(top(&counter, 3), "c (9), a (2), b (2) +1 more");
        assert_eq!(top(&counter, 9), "c (9), a (2), b (2), d (1)");
    }
}
