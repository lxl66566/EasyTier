use std::net::Ipv4Addr;

use crate::{
    config::PeerId,
    proto::common::{NatType, StunInfo},
};

pub const BLACKLIST_TIMEOUT_SEC: u64 = 3600;

// Both-hard-symmetric blind spray (double birthday attack). Each side opens
// `sockets x ports` NAT mappings; the punch lands only when both sides guess
// each other's allocated port for the same flow, i.e. P ~= K1*K2/N^2 per
// round with K = sockets x ports live mappings and N the peer NAT's port
// allocation space. With K ~= 16k per side this is ~6% per round on a full
// 64k allocator and ~33% on a typical ~28k (32768..=60999) allocator; the
// connector's saturating backoff accumulates rounds in the background.
pub const UDP_ARRAY_SIZE_FOR_BOTH_HARD_SYM: usize = 8;
pub const BOTH_HARD_SYM_RANDOM_PORTS_PER_PASS: usize = 2048;
pub const BOTH_HARD_SYM_WAIT_TIME_MS: u64 = 25_000;
// Re-send the same port set mid-window so mappings outlive stingy NAT timers.
pub const BOTH_HARD_SYM_RESPRAY_INTERVAL_MS: u64 = 10_000;
pub const BOTH_HARD_SYM_SPRAY_CHUNK_PORTS: usize = 64;

/// STUN-detected IPv4 public addresses; entries that do not parse as IPv4
/// (e.g. IPv6) are dropped.
pub fn stun_public_ipv4s(stun_info: &StunInfo) -> Vec<Ipv4Addr> {
    stun_info
        .public_ip
        .iter()
        .filter_map(|x| x.parse().ok())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpPunchClientMethod {
    None,
    ConeToCone,
    SymToCone,
    EasySymToEasySym,
    BothHardSym,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpNatType {
    Unknown,
    Open(NatType),
    Cone(NatType),
    EasySymmetric(NatType, bool),
    HardSymmetric(NatType),
}

impl From<NatType> for UdpNatType {
    fn from(nat_type: NatType) -> Self {
        match nat_type {
            NatType::Unknown => UdpNatType::Unknown,
            NatType::OpenInternet => UdpNatType::Open(nat_type),
            NatType::NoPat | NatType::FullCone | NatType::Restricted | NatType::PortRestricted => {
                UdpNatType::Cone(nat_type)
            }
            NatType::Symmetric | NatType::SymUdpFirewall => UdpNatType::HardSymmetric(nat_type),
            NatType::SymmetricEasyInc => UdpNatType::EasySymmetric(nat_type, true),
            NatType::SymmetricEasyDec => UdpNatType::EasySymmetric(nat_type, false),
        }
    }
}

impl From<UdpNatType> for NatType {
    fn from(val: UdpNatType) -> Self {
        match val {
            UdpNatType::Unknown => NatType::Unknown,
            UdpNatType::Open(nat_type) => nat_type,
            UdpNatType::Cone(nat_type) => nat_type,
            UdpNatType::EasySymmetric(nat_type, _) => nat_type,
            UdpNatType::HardSymmetric(nat_type) => nat_type,
        }
    }
}

impl UdpNatType {
    pub fn is_open(&self) -> bool {
        matches!(self, UdpNatType::Open(_))
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, UdpNatType::Unknown)
    }

    pub fn is_sym(&self) -> bool {
        self.is_hard_sym() || self.is_easy_sym()
    }

    pub fn is_hard_sym(&self) -> bool {
        matches!(self, UdpNatType::HardSymmetric(_))
    }

    pub fn is_easy_sym(&self) -> bool {
        matches!(self, UdpNatType::EasySymmetric(_, _))
    }

    pub fn is_cone(&self) -> bool {
        matches!(self, UdpNatType::Cone(_))
    }

    pub fn get_inc_of_easy_sym(&self) -> Option<bool> {
        match self {
            UdpNatType::EasySymmetric(_, inc) => Some(*inc),
            _ => None,
        }
    }

    pub fn get_punch_hole_method(
        &self,
        other: Self,
        disable_sym_hole_punching: bool,
    ) -> UdpPunchClientMethod {
        if disable_sym_hole_punching && self.is_sym() {
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if other.is_unknown() {
            if self.is_sym() {
                return UdpPunchClientMethod::SymToCone;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if self.is_unknown() {
            if other.is_sym() {
                return UdpPunchClientMethod::None;
            } else {
                return UdpPunchClientMethod::ConeToCone;
            }
        }

        if self.is_open() || other.is_open() {
            return UdpPunchClientMethod::None;
        }

        if self.is_cone() {
            if other.is_sym() {
                UdpPunchClientMethod::None
            } else {
                UdpPunchClientMethod::ConeToCone
            }
        } else if self.is_easy_sym() {
            if other.is_hard_sym() {
                UdpPunchClientMethod::None
            } else if other.is_easy_sym() {
                UdpPunchClientMethod::EasySymToEasySym
            } else {
                UdpPunchClientMethod::SymToCone
            }
        } else if self.is_hard_sym() {
            if other.is_hard_sym() {
                UdpPunchClientMethod::BothHardSym
            } else if other.is_sym() {
                UdpPunchClientMethod::None
            } else {
                UdpPunchClientMethod::SymToCone
            }
        } else {
            unreachable!("invalid nat type");
        }
    }

    pub fn can_punch_hole_as_client(
        &self,
        other: Self,
        my_peer_id: PeerId,
        dst_peer_id: PeerId,
        disable_sym_hole_punching: bool,
    ) -> bool {
        match self.get_punch_hole_method(other, disable_sym_hole_punching) {
            UdpPunchClientMethod::None => false,
            UdpPunchClientMethod::ConeToCone | UdpPunchClientMethod::SymToCone => true,
            UdpPunchClientMethod::EasySymToEasySym | UdpPunchClientMethod::BothHardSym => {
                my_peer_id < dst_peer_id
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nat(nat_type: NatType) -> UdpNatType {
        nat_type.into()
    }

    #[test]
    fn nat_type_classification_matches_proto_values() {
        assert_eq!(nat(NatType::Unknown), UdpNatType::Unknown);
        assert_eq!(
            nat(NatType::OpenInternet),
            UdpNatType::Open(NatType::OpenInternet)
        );
        assert_eq!(nat(NatType::FullCone), UdpNatType::Cone(NatType::FullCone));
        assert_eq!(
            nat(NatType::Symmetric),
            UdpNatType::HardSymmetric(NatType::Symmetric)
        );
        assert_eq!(
            nat(NatType::SymmetricEasyInc),
            UdpNatType::EasySymmetric(NatType::SymmetricEasyInc, true)
        );
        assert_eq!(
            nat(NatType::SymmetricEasyDec),
            UdpNatType::EasySymmetric(NatType::SymmetricEasyDec, false)
        );
    }

    #[test]
    fn punch_method_preserves_current_nat_matrix() {
        let cone = nat(NatType::FullCone);
        let hard_sym = nat(NatType::Symmetric);
        let easy_sym = nat(NatType::SymmetricEasyInc);
        let open = nat(NatType::OpenInternet);
        let unknown = nat(NatType::Unknown);

        assert_eq!(
            cone.get_punch_hole_method(cone, false),
            UdpPunchClientMethod::ConeToCone
        );
        assert_eq!(
            hard_sym.get_punch_hole_method(cone, false),
            UdpPunchClientMethod::SymToCone
        );
        assert_eq!(
            cone.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::None
        );
        assert_eq!(
            easy_sym.get_punch_hole_method(easy_sym, false),
            UdpPunchClientMethod::EasySymToEasySym
        );
        assert_eq!(
            easy_sym.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::None
        );
        assert_eq!(
            hard_sym.get_punch_hole_method(unknown, false),
            UdpPunchClientMethod::SymToCone
        );
        assert_eq!(
            unknown.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::None
        );
        assert_eq!(
            open.get_punch_hole_method(cone, false),
            UdpPunchClientMethod::None
        );
    }

    #[test]
    fn disabled_symmetric_punching_keeps_existing_fallback() {
        let cone = nat(NatType::FullCone);
        let hard_sym = nat(NatType::Symmetric);
        let easy_sym = nat(NatType::SymmetricEasyInc);

        assert_eq!(
            hard_sym.get_punch_hole_method(cone, true),
            UdpPunchClientMethod::ConeToCone
        );
        assert_eq!(
            hard_sym.get_punch_hole_method(easy_sym, true),
            UdpPunchClientMethod::None
        );
    }

    #[test]
    fn easy_sym_to_easy_sym_uses_lower_peer_id_as_client() {
        let easy_sym = nat(NatType::SymmetricEasyInc);

        assert!(easy_sym.can_punch_hole_as_client(easy_sym, 1, 2, false));
        assert!(!easy_sym.can_punch_hole_as_client(easy_sym, 2, 1, false));
    }

    #[test]
    fn both_hard_sym_covers_hard_sym_pairs_with_lower_peer_id_client() {
        let hard_sym = nat(NatType::Symmetric);
        let sym_firewall = nat(NatType::SymUdpFirewall);
        let easy_sym = nat(NatType::SymmetricEasyInc);

        assert_eq!(
            hard_sym.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::BothHardSym
        );
        assert_eq!(
            hard_sym.get_punch_hole_method(sym_firewall, false),
            UdpPunchClientMethod::BothHardSym
        );
        assert_eq!(
            sym_firewall.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::BothHardSym
        );
        // easy x hard keeps no path: blind spray odds near the hard side's
        // allocation behavior are covered by other methods, not this one.
        assert_eq!(
            easy_sym.get_punch_hole_method(hard_sym, false),
            UdpPunchClientMethod::None
        );
        assert_eq!(
            hard_sym.get_punch_hole_method(easy_sym, false),
            UdpPunchClientMethod::None
        );

        assert!(hard_sym.can_punch_hole_as_client(hard_sym, 1, 2, false));
        assert!(!hard_sym.can_punch_hole_as_client(hard_sym, 2, 1, false));
        // disable_sym_hole_punching turns any sym x sym pair into None.
        assert_eq!(
            hard_sym.get_punch_hole_method(hard_sym, true),
            UdpPunchClientMethod::None
        );
        assert!(!hard_sym.can_punch_hole_as_client(hard_sym, 1, 2, true));
    }
}
