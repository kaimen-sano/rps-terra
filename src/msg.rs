use cosmwasm_std::Addr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::{GameMove, Match};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub admin: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Starts a new "rock paper scissors" game, given the opponent and the first move.
    StartGame {
        opponent: Addr,
        first_move: GameMove,
    },
    /// Responds to a "rock paper scissors" game, given the host and the move to respond with.
    ///
    /// Must be called by the `opponent` in the game.
    Respond { host: Addr, response_move: GameMove },

    /// Passes the admin role on to another address. Must be called by admin.
    UpdateAdmin { new_admin: Option<Addr> },
    /// Add a blacklisted user. Must be called by admin.
    AddBlacklisted { addr: Addr },
    /// Remove a blacklisted user. Must be called by admin.
    RemoveBlacklisted { addr: Addr },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetHostMatches returns the matches in which an address was the host.
    GetHostMatches { host_address: Addr },
    // GetOpponentMatches returns the matches in which a user was the opponent.
    GetOpponentMatches { opponent_address: Addr },
    // GetAdmin returns the address for which the contract has the admin set to.
    GetAdmin {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct HostMatchesResponse {
    pub matches: Vec<Match>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct OpponentMatchesResponse {
    pub matches: Vec<Match>,
}
