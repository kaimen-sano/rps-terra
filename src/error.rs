use cosmwasm_std::StdError;
use cw_controllers::{AdminError, HookError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Admin(#[from] AdminError),

    #[error("{0}")]
    Hook(#[from] HookError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Already playing a game")]
    GameInProgress {},

    #[error("No game was found to respond to")]
    NoGame {},

    #[error("Blacklisted from creating matches")]
    Blacklisted {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}
