//! Summarising a long list of names by their common path prefixes.

use std::collections::BTreeSet;

/// Shrink a list of `/`-separated names to at most `limit` entries by
/// replacing the deepest path segments with a `*`, deepest first.
///
/// An application that wrote a thousand objects under `uploads/2024/` was not
/// granted those thousand keys; it was granted the prefix. Names without a
/// path (a queue, a function, an image called `nginx`) are never merged, so
/// the result can still exceed the limit, and the first segment (a bucket, a
/// registry) is never given up. When the limit cannot be met, widening stops
/// at the point where it last made the list shorter.
pub fn generalize(resources: &BTreeSet<String>, limit: usize) -> Vec<String> {
    if resources.contains("*") {
        return vec!["*".to_string()];
    }
    let mut paths: BTreeSet<Vec<&str>> = prune(
        resources
            .iter()
            .map(|resource| resource.split('/').collect())
            .collect(),
    );
    // The limit may be out of reach. Remember the first point at which the
    // list was as short as it ever gets, so as not to keep widening for
    // nothing.
    let mut shortest = paths.clone();
    while paths.len() > limit {
        let depth = paths.iter().map(Vec::len).max().unwrap_or(0);
        if depth < 2 {
            break; // nothing left with a path to shorten
        }
        let widened: BTreeSet<Vec<&str>> = paths
            .iter()
            .map(|path| {
                let mut path = path.clone();
                if path.len() == depth && path[depth - 1] != "*" {
                    path[depth - 1] = "*"; // a/b/c -> a/b/*
                } else if path.len() == depth && depth > 2 {
                    path.truncate(depth - 2); // a/b/* -> a/*, but never a/* -> *
                    path.push("*");
                }
                path
            })
            .collect();
        if widened == paths {
            break;
        }
        paths = prune(widened);
        if paths.len() < shortest.len() {
            shortest = paths.clone();
        }
    }
    if paths.len() > limit {
        paths = shortest;
    }
    let mut out: Vec<String> = paths.iter().map(|path| path.join("/")).collect();
    out.sort();
    out
}

/// Drop paths already covered by a wildcard elsewhere in the set.
fn prune(paths: BTreeSet<Vec<&str>>) -> BTreeSet<Vec<&str>> {
    let wildcards: BTreeSet<Vec<&str>> = paths
        .iter()
        .filter(|path| path.last() == Some(&"*"))
        .map(|path| path[..path.len() - 1].to_vec())
        .collect();
    paths
        .into_iter()
        .filter(|path| {
            // A wildcard is not covered by its own prefix.
            let own = usize::from(path.last() == Some(&"*"));
            !(1..path.len() - own).any(|n| wildcards.contains(&path[..n]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: impl IntoIterator<Item = String>) -> BTreeSet<String> {
        items.into_iter().collect()
    }

    #[test]
    fn generalize_collapses_deepest_paths_first() {
        let mut keys = set((0..50).map(|n| format!("arn:aws:s3:::b/up/2026/{n}.jpg")));
        keys.insert("arn:aws:s3:::b/config.json".to_string());
        assert_eq!(
            generalize(&keys, 10),
            ["arn:aws:s3:::b/config.json", "arn:aws:s3:::b/up/2026/*"]
        );
    }

    #[test]
    fn generalize_keeps_going_up_but_never_past_the_bucket() {
        let keys = set((0..50).map(|n| format!("arn:aws:s3:::b/tenant-{n}/data/file")));
        assert_eq!(generalize(&keys, 10), ["arn:aws:s3:::b/*"]);
        let buckets = set([
            "arn:aws:s3:::a/*".to_string(),
            "arn:aws:s3:::b/*".to_string(),
        ]);
        assert_eq!(
            generalize(&buckets, 1),
            ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]
        );
    }

    #[test]
    fn generalize_leaves_pathless_resources_alone() {
        let queues = set((0..5).map(|n| format!("arn:aws:sqs:us-east-1:1:q{n}")));
        assert_eq!(
            generalize(&queues, 2),
            queues.iter().cloned().collect::<Vec<_>>()
        );
        let any = set(["*".to_string(), "arn:aws:s3:::b".to_string()]);
        assert_eq!(generalize(&any, 10), ["*"]);
        let covered = set([
            "arn:aws:s3:::b/*".to_string(),
            "arn:aws:s3:::b/k".to_string(),
        ]);
        assert_eq!(generalize(&covered, 10), ["arn:aws:s3:::b/*"]);
    }

    #[test]
    fn generalize_does_not_widen_past_the_point_of_helping() {
        let images = set([
            "busybox".to_string(),
            "registry.example.com/shop/api".to_string(),
            "registry.example.com/shop/worker".to_string(),
        ]);
        // "busybox" can never merge, so one entry is out of reach; stop at
        // the shop path rather than giving up the whole registry.
        assert_eq!(
            generalize(&images, 1),
            ["busybox", "registry.example.com/shop/*"]
        );

        // A step that does not shorten the list can still be on the way to
        // one that does.
        let nested = set([
            "a/b/c/1".to_string(),
            "a/b/c/2".to_string(),
            "a/d/e".to_string(),
        ]);
        assert_eq!(generalize(&nested, 1), ["a/*"]);
        assert_eq!(generalize(&nested, 2), ["a/b/c/*", "a/d/e"]);
    }
}
