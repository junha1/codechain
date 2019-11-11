// Copyright 2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either verion 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::collections::{BTreeMap, BTreeSet};

use super::{PriorityMessage, SortitionRound};

/// Stores priority messages with sortition round as a key
#[derive(Default)]
pub struct PriorityMessageCollector {
    messages: BTreeMap<SortitionRound, BTreeSet<PriorityMessage>>,
}

impl PriorityMessageCollector {
    pub fn insert(&mut self, message: PriorityMessage, round: SortitionRound) {
        self.messages.entry(round).or_insert_with(Default::default).insert(message);
    }

    pub fn get_highest_priority_message(&self, round: &SortitionRound) -> Option<PriorityMessage> {
        self.messages.get(&round).and_then(|set| set.iter().rev().next()).cloned()
    }

    /// Throw away priority messages older than the given round.
    pub fn throw_away_old(&mut self, round: &SortitionRound) {
        let new_collector = self.messages.split_off(round);
        self.messages = new_collector;
    }
}

#[cfg(test)]
mod priority_message_collector_tests {
    use super::*;
    use crate::consensus::{Priority, PriorityInfo, SeedInfo};

    fn create_message_with_priority_and_signer_idx(priority: Priority, signer_idx: usize) -> PriorityMessage {
        PriorityMessage {
            seed_info: SeedInfo::from_fields(signer_idx, vec![0x0], vec![0x22]),
            priority_info: PriorityInfo::create_from_members(priority, 0, vec![], vec![]),
        }
    }

    #[test]
    fn compare_sortition_info() {
        let greater_priority_info_summary = create_message_with_priority_and_signer_idx(0xffu64.into(), 0);
        let less_priority_info_summary = create_message_with_priority_and_signer_idx(0x7fu64.into(), 1);
        assert!(greater_priority_info_summary > less_priority_info_summary);
    }

    #[test]
    fn compare_sortition_info2() {
        let greater_priority_info_summary = create_message_with_priority_and_signer_idx(0x5555_5544u64.into(), 0);
        let less_priority_info_summary = create_message_with_priority_and_signer_idx(0x5555_5523u64.into(), 22);
        assert!(greater_priority_info_summary > less_priority_info_summary);
    }

    fn add_fixed_priorities(collector: &mut PriorityMessageCollector, round: SortitionRound) {
        [0x55u64, 0xffu64, 0x44u64, 0xeeu64]
            .iter()
            .zip([1, 2, 3, 4].iter())
            .map(|(priority, idx)| create_message_with_priority_and_signer_idx((*priority).into(), *idx))
            .for_each(|sortition_info| collector.insert(sortition_info, round));
    }

    #[test]
    fn insert_and_get_highest() {
        let mut collector: PriorityMessageCollector = Default::default();
        let round = SortitionRound {
            height: 1,
            view: 0,
        };
        add_fixed_priorities(&mut collector, round);
        assert_eq!(
            collector.get_highest_priority_message(&round).unwrap(),
            create_message_with_priority_and_signer_idx(0xffu64.into(), 2)
        );
    }

    #[test]
    fn throw_away_old() {
        let mut collector: PriorityMessageCollector = Default::default();
        let rounds = [(1, 0), (3, 1), (5, 2), (100, 7), (0, 8)].iter().map(|(height, view)| SortitionRound {
            height: *height,
            view: *view,
        });
        rounds.clone().for_each(|round| add_fixed_priorities(&mut collector, round));
        let target_round = SortitionRound {
            height: 5,
            view: 2,
        };
        collector.throw_away_old(&target_round);
        rounds
            .clone()
            .filter(|round| *round >= target_round)
            .for_each(|round_gte| assert!(collector.get_highest_priority_message(&round_gte).is_some()));
        rounds
            .filter(|round| *round < target_round)
            .for_each(|round_lt| assert!(collector.get_highest_priority_message(&round_lt).is_none()))
    }
}
