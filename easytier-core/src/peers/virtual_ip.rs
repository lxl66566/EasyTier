//! Shared assignment policy for virtual IPv4 prefixes handed to VPN portal
//! clients and locally attached peers.
//!
//! Overlapping assignments make mesh-side prefix routing ambiguous: packets
//! for one client can be delivered into another client's tunnel. Both intake
//! layers therefore validate candidates with the same predicates defined here.

use std::net::Ipv4Addr;

use cidr::Ipv4Inet;

/// Special-purpose IPv4 ranges that must never carry virtual-peer traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecialIpv4Range {
    /// `0.0.0.0/8`
    Unspecified,
    /// `127.0.0.0/8`
    Loopback,
    /// `169.254.0.0/16`
    LinkLocal,
    /// `224.0.0.0/4`
    Multicast,
    /// `240.0.0.0/4`, including the broadcast address
    Reserved,
}

impl SpecialIpv4Range {
    const ALL: [Self; 5] = [
        Self::Unspecified,
        Self::Loopback,
        Self::LinkLocal,
        Self::Multicast,
        Self::Reserved,
    ];

    fn network(self) -> Ipv4Inet {
        let (address, prefix) = match self {
            Self::Unspecified => (Ipv4Addr::UNSPECIFIED, 8),
            Self::Loopback => (Ipv4Addr::new(127, 0, 0, 0), 8),
            Self::LinkLocal => (Ipv4Addr::new(169, 254, 0, 0), 16),
            Self::Multicast => (Ipv4Addr::new(224, 0, 0, 0), 4),
            Self::Reserved => (Ipv4Addr::new(240, 0, 0, 0), 4),
        };
        Ipv4Inet::new(address, prefix).expect("special ranges use valid prefixes")
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
        }
    }
}

/// Two assignments conflict when either network contains the other's host
/// address. This covers identical, nested, and partially overlapping CIDRs.
pub(crate) fn ipv4_assignments_overlap(a: Ipv4Inet, b: Ipv4Inet) -> bool {
    a.network().contains(&b.address()) || b.network().contains(&a.address())
}

/// Returns the special-purpose range that `assignment`'s network overlaps.
/// The whole network is checked, not just the host address, so a wide prefix
/// such as `126.0.0.1/7` cannot swallow loopback.
pub(crate) fn special_ipv4_range_conflict(assignment: Ipv4Inet) -> Option<SpecialIpv4Range> {
    SpecialIpv4Range::ALL
        .into_iter()
        .find(|range| ipv4_assignments_overlap(assignment, range.network()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inet(octets: [u8; 4], prefix: u8) -> Ipv4Inet {
        Ipv4Inet::new(Ipv4Addr::from(octets), prefix).unwrap()
    }

    #[test]
    fn assignment_overlap_requires_intersecting_networks() {
        let host_a = inet([10, 0, 0, 1], 24);
        assert!(ipv4_assignments_overlap(host_a, inet([10, 0, 0, 9], 24)));
        assert!(ipv4_assignments_overlap(inet([10, 0, 0, 9], 24), host_a));
        assert!(ipv4_assignments_overlap(host_a, inet([10, 0, 5, 1], 16)));
        assert!(ipv4_assignments_overlap(inet([10, 0, 5, 1], 16), host_a));

        assert!(!ipv4_assignments_overlap(host_a, inet([10, 0, 1, 1], 24)));
        assert!(!ipv4_assignments_overlap(
            inet([10, 0, 0, 1], 16),
            inet([10, 1, 0, 1], 16)
        ));
    }

    #[test]
    fn special_ranges_reject_direct_and_covering_assignments() {
        assert_eq!(
            special_ipv4_range_conflict(inet([127, 0, 0, 5], 8)),
            Some(SpecialIpv4Range::Loopback)
        );
        assert_eq!(
            special_ipv4_range_conflict(inet([169, 254, 0, 9], 16)),
            Some(SpecialIpv4Range::LinkLocal)
        );
        assert_eq!(
            special_ipv4_range_conflict(inet([224, 0, 0, 5], 24)),
            Some(SpecialIpv4Range::Multicast)
        );
        assert_eq!(
            special_ipv4_range_conflict(inet([255, 0, 0, 9], 8)),
            Some(SpecialIpv4Range::Reserved)
        );
        // A /7 spanning 126.0.0.0-127.255.255.255 covers loopback.
        assert_eq!(
            special_ipv4_range_conflict(inet([126, 0, 0, 1], 7)),
            Some(SpecialIpv4Range::Loopback)
        );

        assert_eq!(special_ipv4_range_conflict(inet([10, 82, 0, 2], 24)), None);
        assert_eq!(special_ipv4_range_conflict(inet([100, 64, 0, 1], 10)), None);
    }
}
