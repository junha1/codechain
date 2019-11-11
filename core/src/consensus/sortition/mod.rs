// Copyright 2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![allow(dead_code)]

mod binom_cdf;
mod draw;
pub mod seed;
pub mod vrf_sortition;

use std::cmp::Ordering;

use ckey::Public;
use vrf::openssl::{Error as VRFError, ECVRF};

pub use self::seed::{SeedInfo, VRFSeed};
use self::vrf_sortition::{Priority, PriorityInfo, VRFSortition};
use crate::consensus::{Height, View};

#[derive(Clone, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable)]
pub struct PriorityMessage {
    pub seed_info: SeedInfo,
    pub priority_info: PriorityInfo,
}

impl Ord for PriorityMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority().cmp(&other.priority())
    }
}

impl PartialOrd for PriorityMessage {
    fn partial_cmp(&self, other:&Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PriorityMessage {
    pub fn seed(&self) -> &VRFSeed {
        self.seed_info.seed()
    }

    pub fn seed_signer_idx(&self) -> usize {
        self.seed_info.signer_idx()
    }

    pub fn verify_seed(
        &self,
        height: Height,
        view: View,
        prev_seed: &VRFSeed,
        signer_public: &Public,
        vrf_inst: &mut ECVRF,
    ) -> Result<bool, VRFError> {
        self.seed_info.verify(height, view, prev_seed, signer_public, vrf_inst)
    }

    pub fn verify_priority(
        &self,
        signer_public: &Public,
        voting_power: u64,
        sortition_scheme: &mut VRFSortition,
    ) -> Result<bool, VRFError> {
        // fast verification first
        Ok(self.priority_info.verify_sub_user_idx(
            voting_power,
            sortition_scheme.total_power,
            sortition_scheme.expectation,
        ) && self.priority_info.verify_priority()
            && self.priority_info.verify_vrf_hash(signer_public, self.seed(), &mut sortition_scheme.vrf_inst)?)
    }

    pub fn priority(&self) -> Priority {
        self.priority_info.priority()
    }
}

#[cfg(test)]
mod priority_message_tests {
    use ccrypto::sha256;
    use ckey::KeyPair;
    use rlp::rlp_encode_and_decode_test;
    use vrf::openssl::{CipherSuite, ECVRF};

    use super::super::signer::EngineSigner;
    use super::*;
    #[test]
    fn check_priority_message_verification() {
        let secret = sha256("secret key");
        let signer = EngineSigner::create_engine_signer_with_secret(secret);
        let pub_key = *KeyPair::from_private(secret.into()).expect("Valid private key").public();

        let wrong_pub_key =
            *KeyPair::from_private(sha256("wrong_secret_key2").into()).expect("Valid private key").public();

        let seed = sha256("seed");
        let ec_vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_SVDW).unwrap();
        let mut sortition_scheme = VRFSortition {
            total_power: 100,
            expectation: 71.85,
            vrf_inst: ec_vrf,
        };
        let voting_power = 50;
        let priority_info =
            sortition_scheme.create_highest_priority_info(seed.into(), &signer, voting_power).unwrap().unwrap();

        let priority_message = PriorityMessage {
            seed_info: SeedInfo::from_fields(0, seed.to_vec(), vec![]),
            priority_info,
        };
        assert!(priority_message.verify_priority(&pub_key, voting_power, &mut sortition_scheme).unwrap());
        assert!(priority_message.verify_priority(&wrong_pub_key, voting_power, &mut sortition_scheme).is_err());
    }

    #[test]
    fn test_encode_and_decode_priority_message() {
        let signer = EngineSigner::create_engine_signer_with_secret(sha256("secret_key"));
        let seed = sha256("seed");
        let ec_vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_SVDW).unwrap();
        let mut sortition_scheme = VRFSortition {
            total_power: 100,
            expectation: 71.85,
            vrf_inst: ec_vrf,
        };
        let voting_power = 50;
        let priority_info =
            sortition_scheme.create_highest_priority_info(seed.into(), &signer, voting_power).unwrap().unwrap();

        let priority_message = PriorityMessage {
            seed_info: SeedInfo::from_fields(0, seed.to_vec(), vec![]),
            priority_info,
        };
        rlp_encode_and_decode_test!(priority_message);
    }
}
