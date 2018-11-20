// Copyright 2018 Kodebox, Inc.
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

use std::option::Option;

use super::route::TreeRoute;
use primitives::H256;

/// Describes how best block is changed
#[derive(Debug, Clone, PartialEq)]
pub enum BestBlockChanged {
    /// Cannonical chain is appended.
    CanonChainAppended {
        new_best_hash: H256,
    },
    /// Nothing changed.
    None,
    /// It's part of the fork which should become canon chain,
    /// because its total score is higher than current
    /// canon chain score.
    BranchBecomingCanonChain {
        new_best_hash: H256,
        tree_route: TreeRoute,
    },
}

impl BestBlockChanged {
    pub fn new_best_hash(&self) -> Option<H256> {
        match self {
            BestBlockChanged::CanonChainAppended {
                new_best_hash,
            } => Some(*new_best_hash),
            BestBlockChanged::BranchBecomingCanonChain {
                new_best_hash,
                ..
            } => Some(*new_best_hash),
            BestBlockChanged::None => None,
        }
    }
}
