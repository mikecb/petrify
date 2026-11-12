//! CIDR blocks, and covering a set of peers with as few of them as allowed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Prefix lengths tried, in order, when peers must be summarised.
const V4_STEPS: [u8; 8] = [32, 28, 24, 20, 16, 12, 8, 0];
const V6_STEPS: [u8; 6] = [128, 64, 56, 48, 32, 0];

/// A CIDR block. Ordered by family, then address, then prefix length, which
/// puts a block directly before the blocks it contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    pub(crate) v6: bool,
    bits: u128,
    pub(crate) prefix: u8,
}

impl Net {
    /// The block of length `prefix` containing `address`.
    pub fn new(address: IpAddr, prefix: u8) -> Net {
        let (v6, bits) = match address {
            IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
            IpAddr::V6(v6) => (true, u128::from(v6)),
        };
        let width = if v6 { 128 } else { 32 };
        let prefix = prefix.min(width);
        Net {
            v6,
            bits: bits & mask(prefix, width),
            prefix,
        }
    }

    /// `10.0.0.0/16`, or a bare address meaning just that host.
    pub fn parse(text: &str) -> Option<Net> {
        match text.split_once('/') {
            None => Some(Net::host(text.parse().ok()?)),
            Some((address, prefix)) => {
                let address: IpAddr = address.parse().ok()?;
                let prefix: u8 = prefix.parse().ok()?;
                (prefix <= if address.is_ipv6() { 128 } else { 32 })
                    .then(|| Net::new(address, prefix))
            }
        }
    }

    pub(crate) fn host(address: IpAddr) -> Net {
        Net::new(address, 128)
    }

    fn width(&self) -> u8 {
        if self.v6 { 128 } else { 32 }
    }

    fn covers(&self, other: &Net) -> bool {
        self.v6 == other.v6
            && self.prefix <= other.prefix
            && other.bits & mask(self.prefix, self.width()) == self.bits
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.covers(&Net::host(address))
    }

    /// The block one bit shorter that contains this one.
    fn parent(&self) -> Net {
        let prefix = self.prefix.saturating_sub(1);
        Net {
            v6: self.v6,
            bits: self.bits & mask(prefix, self.width()),
            prefix,
        }
    }
}

fn mask(prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    let all = if width == 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    all & (u128::MAX << (width - prefix))
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.v6 {
            write!(f, "{}/{}", Ipv6Addr::from(self.bits), self.prefix)
        } else {
            write!(f, "{}/{}", Ipv4Addr::from(self.bits as u32), self.prefix)
        }
    }
}

/// The smallest list of blocks covering exactly the same addresses.
pub(super) fn collapse(mut nets: Vec<Net>) -> Vec<Net> {
    loop {
        nets.sort();
        // Sorted, a block can only be covered by the last block kept.
        let mut kept: Vec<Net> = Vec::with_capacity(nets.len());
        for net in nets {
            if !kept.last().is_some_and(|last| last.covers(&net)) {
                kept.push(net);
            }
        }
        // With covered blocks gone, the two halves of a block are adjacent.
        let mut merged = Vec::with_capacity(kept.len());
        let mut index = 0;
        while index < kept.len() {
            let (this, next) = (kept[index], kept.get(index + 1));
            let siblings = next.is_some_and(|next| {
                this.prefix > 0 && this.prefix == next.prefix && this.parent() == next.parent()
            });
            merged.push(if siblings { this.parent() } else { this });
            index += if siblings { 2 } else { 1 };
        }
        if merged.len() == kept.len() {
            return merged;
        }
        nets = merged;
    }
}

fn private_ranges() -> [Net; 5] {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    ]
    .map(|range| Net::parse(range).expect("constant CIDR"))
}

/// Cover the peers with at most `limit` CIDR blocks per address family,
/// widening prefixes only as far as needed. Private addresses are never
/// widened past their private range, so a noisy internal service does not
/// turn into a rule for the whole internet.
pub fn summarize(peers: impl IntoIterator<Item = IpAddr>, limit: usize) -> Vec<Net> {
    let private = private_ranges();
    let widen = |address: IpAddr, prefix: u8| {
        let net = Net::new(address, prefix);
        match private.iter().find(|range| range.contains(address)) {
            Some(range) if net.prefix < range.prefix => *range,
            _ => net,
        }
    };
    let peers: Vec<IpAddr> = peers.into_iter().collect();
    let mut result = Vec::new();
    for (v6, steps) in [(false, &V4_STEPS[..]), (true, &V6_STEPS[..])] {
        let family: Vec<IpAddr> = peers
            .iter()
            .copied()
            .filter(|a| a.is_ipv6() == v6)
            .collect();
        let mut nets = Vec::new();
        for &prefix in steps {
            nets = collapse(
                family
                    .iter()
                    .map(|&address| widen(address, prefix))
                    .collect(),
            );
            if nets.len() <= limit {
                break;
            }
        }
        result.extend(nets);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn cidrs(peers: &[String], limit: usize) -> Vec<String> {
        summarize(peers.iter().map(|peer| ip(peer)), limit)
            .iter()
            .map(Net::to_string)
            .collect()
    }

    fn peers(pattern: &str, numbers: impl IntoIterator<Item = u32>) -> Vec<String> {
        numbers
            .into_iter()
            .map(|n| pattern.replace('N', &n.to_string()))
            .collect()
    }

    #[test]
    fn summarize_keeps_exact_hosts_when_they_fit() {
        let two = ["203.0.113.7".to_string(), "198.51.100.20".to_string()];
        assert_eq!(cidrs(&two, 8), ["198.51.100.20/32", "203.0.113.7/32"]);
        assert_eq!(cidrs(&peers("10.0.0.N", 4..=5), 8), ["10.0.0.4/31"]);
        assert_eq!(cidrs(&peers("10.0.0.N", 0..=255), 8), ["10.0.0.0/24"]);
    }

    #[test]
    fn summarize_widens_only_as_far_as_needed() {
        let odd = peers("203.0.113.N", (1..40).step_by(2));
        assert_eq!(cidrs(&odd, 4), ["203.0.113.0/27", "203.0.113.32/28"]);
        assert_eq!(cidrs(&odd, 1), ["203.0.113.0/24"]);
    }

    #[test]
    fn summarize_never_widens_private_peers_to_the_internet() {
        let mut internal = peers("10.N.0.1", 0..40);
        internal.extend(peers("192.168.N.1", 0..40));
        assert_eq!(cidrs(&internal, 2), ["10.0.0.0/8", "192.168.0.0/16"]);

        let mut scattered = peers("N.1.1.1", 11..60);
        scattered.push("10.1.1.1".to_string());
        assert_eq!(cidrs(&scattered, 2), ["0.0.0.0/0"]);
    }

    #[test]
    fn summarize_handles_each_address_family_separately() {
        let mixed = ["2001:db8::1".to_string(), "203.0.113.7".to_string()];
        assert_eq!(cidrs(&mixed, 1), ["203.0.113.7/32", "2001:db8::1/128"]);
        let v6 = peers("2001:db8:0:1::N", 1..=9);
        assert_eq!(cidrs(&v6, 2), ["2001:db8:0:1::/64"]);
    }
}
