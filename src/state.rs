use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cw_controllers::{Admin, Hooks};
use cw_storage_plus::Map;

pub const ADMIN: Admin = Admin::new("admin");
pub const HOOKS: Hooks = Hooks::new("hooks");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Match {
    pub host: Addr,
    pub opponent: Addr,
    pub host_move: GameMove,
    pub opponent_move: Option<GameMove>,
    pub game_result: Option<GameResult>,
}

pub const MATCHES: Map<(&Addr, &Addr), Match> = Map::new("matches");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum GameMove {
    Rock,
    Paper,
    Scissors,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum GameResult {
    HostWins,
    OpponentWins,
    Tie,
}
