#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdResult,
};
use cw0::maybe_addr;
use cw2::set_contract_version;
use cw_controllers::AdminResponse;

use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, HostMatchesResponse, InstantiateMsg, OpponentMatchesResponse, QueryMsg,
};
use crate::state::{GameMove, GameResult, Match, ADMIN, HOOKS, MATCHES};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:rock-paper-scissors-terra";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiates the contract
///
/// # Errors
/// Errors if an `admin` is passed and is not a valid address.
///
/// Errors if saving to state fails.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let api = deps.api;
    let admin = msg.admin;
    ADMIN.set(deps, maybe_addr(api, admin)?)?;

    Ok(Response::new().add_attribute("method", "instantiate"))
}

/// Executes a message to the contract.
///
/// # Errors
/// Errors if unable to execute the message.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let api = deps.api;

    match msg {
        ExecuteMsg::StartGame {
            opponent,
            first_move,
        } => try_start_game(deps, info, &opponent, &first_move),
        ExecuteMsg::Respond {
            host,
            response_move,
        } => try_respond(deps, info, &host, &response_move),
        ExecuteMsg::UpdateAdmin { new_admin } => try_update_admin(deps, info, new_admin),
        ExecuteMsg::AddBlacklisted { addr } => {
            Ok(HOOKS.execute_add_hook(&ADMIN, deps, info, api.addr_validate(addr.as_str())?)?)
        }
        ExecuteMsg::RemoveBlacklisted { addr } => {
            Ok(HOOKS.execute_remove_hook(&ADMIN, deps, info, api.addr_validate(addr.as_str())?)?)
        }
    }
}

/// Starts a new game with an opponent.
///
/// # Errors
/// Errors if the sender is blacklisted from creating a new match (`ContractError::Blacklisted`)
///
/// Errors if there is already an active match between the pair (`ContractError::GameInProgress`)
///
/// Errors if unable to save to state.
pub fn try_start_game(
    deps: DepsMut,
    info: MessageInfo,
    opponent: &Addr,
    first_move: &GameMove,
) -> Result<Response, ContractError> {
    // validate opponent is a valid address
    let opponent = deps.api.addr_validate(opponent.as_str())?;

    // validate host is not blacklisted
    if HOOKS
        .query_hooks(deps.as_ref())?
        .hooks
        .contains(&info.sender.to_string())
    {
        return Err(ContractError::Blacklisted {});
    }

    // validate player pair does not already have an active match
    if MATCHES.has(deps.storage, (&info.sender, &opponent)) {
        return Err(ContractError::GameInProgress {});
    }

    // create new match
    MATCHES.save(
        deps.storage,
        (&info.sender, &opponent),
        &Match {
            host: info.sender.clone(),
            opponent: opponent.clone(),
            host_move: first_move.clone(),
            game_result: None,
            opponent_move: None,
        },
    )?;

    Ok(Response::new()
        .add_attribute("method", "start_game")
        .add_attribute("host", info.sender)
        .add_attribute("opponent", opponent)
        .add_attribute(
            "host_move",
            match first_move {
                GameMove::Paper => "paper",
                GameMove::Rock => "rock",
                GameMove::Scissors => "scissors",
            },
        ))
}

/// Responds with a move to a match.
///
/// # Errors
/// Errors if the host address is not a valid address
///
/// Errors if there is no game between the pair (`ContractError::NoGame`)
pub fn try_respond(
    deps: DepsMut,
    info: MessageInfo,
    host: &Addr,
    response_move: &GameMove,
) -> Result<Response, ContractError> {
    // validate host is a valid address
    let host = deps.api.addr_validate(host.as_str())?;

    // get match
    let game = MATCHES
        .may_load(deps.storage, (&host, &info.sender))?
        .ok_or(ContractError::NoGame {})?;

    let winner = match game.host_move {
        // paper <-> rock
        GameMove::Paper if response_move == &GameMove::Rock => GameResult::HostWins,
        GameMove::Rock if response_move == &GameMove::Paper => GameResult::OpponentWins,

        // scissors <-> rock
        GameMove::Rock if response_move == &GameMove::Scissors => GameResult::HostWins,
        GameMove::Scissors if response_move == &GameMove::Rock => GameResult::OpponentWins,

        // paper <-> scissors
        GameMove::Scissors if response_move == &GameMove::Paper => GameResult::HostWins,
        GameMove::Paper if response_move == &GameMove::Scissors => GameResult::OpponentWins,

        // otherwise, it must be a draw
        _ => GameResult::Tie,
    };

    // delete match
    MATCHES.remove(deps.storage, (&host, &info.sender));

    Ok(Response::new()
        .add_attribute("method", "response")
        .add_attribute("host", host)
        .add_attribute("opponent", info.sender)
        .add_attribute(
            "winner",
            match winner {
                GameResult::HostWins => "host",
                GameResult::OpponentWins => "opponent",
                GameResult::Tie => "tie",
            },
        ))
}

/// Updates the admin of the contract
///
/// # Errors
/// Errors if the new address is not a valid address
///
/// Errors if the new admin was failed to be saved
pub fn try_update_admin(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: Option<Addr>,
) -> Result<Response, ContractError> {
    let api = deps.api;

    Ok(ADMIN.execute_update_admin(
        deps,
        info,
        new_admin
            .map(|new_admin| api.addr_validate(new_admin.as_str()))
            .transpose()?,
    )?)
}

/// Queries some data from the contract.
///
/// # Errors
/// Errors if unable to query the contract
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetHostMatches { host_address } => {
            to_binary(&query_host_matches(deps, &host_address)?)
        }
        QueryMsg::GetOpponentMatches { opponent_address } => {
            to_binary(&query_opponent_matches(deps, &opponent_address))
        }
        QueryMsg::GetAdmin {} => to_binary(&query_admin(deps)?),
    }
}

fn query_host_matches(deps: Deps, address: &Addr) -> StdResult<HostMatchesResponse> {
    // validate address
    let address = deps.api.addr_validate(&address.to_string())?;

    let matches: Vec<_> = MATCHES
        .prefix(&address)
        .range(deps.storage, None, None, Order::Ascending)
        // turn from Result<(Addr, State), StdError> into Result<State, StdError>
        .map(|r| r.map(|(_, v)| v))
        .collect::<StdResult<Vec<_>>>()?;

    Ok(HostMatchesResponse { matches })
}

fn query_opponent_matches(deps: Deps, address: &Addr) -> OpponentMatchesResponse {
    let matches = MATCHES
        .range(deps.storage, None, None, Order::Ascending)
        .filter_map(|r| {
            match r {
                // warning: this probably has potential for exploits given that we use an unknown length address
                // so a legitimate user with a name ending with CCCC could be exploited by a user who has XXCCCC
                // cosmwasm-storage-plus v11.0 fixes this as it will give us the full (&Addr, &Addr) key rather than
                // a Vec<u8> key.
                Ok((k, v)) if k.ends_with(&address.as_bytes().to_vec()) => Some(v),
                _ => None,
            }
        })
        .collect::<Vec<_>>();

    OpponentMatchesResponse { matches }
}

fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    ADMIN.query_admin(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::StdError::GenericErr;
    use cosmwasm_std::{coins, from_binary};
    use cw_controllers::AdminError;

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(&[]);

        let msg = InstantiateMsg { admin: None };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn cant_start_with_invalid_address() {
        let mut deps = mock_dependencies(&[]);
        let create_info = mock_info("creator", &[]);

        let msg = ExecuteMsg::StartGame {
            opponent: Addr::unchecked(""),
            first_move: GameMove::Paper,
        };

        let expected_err_msg = "Invalid input: human address too short".to_string();

        let res = execute(deps.as_mut(), mock_env(), create_info, msg).unwrap_err();

        match res {
            ContractError::Std(GenericErr { msg }) => {
                assert_eq!(expected_err_msg, msg)
            }
            _ => panic!("Must return ParseError on address"),
        }
    }

    #[test]
    fn can_start_game_with_valid_address() {
        let mut deps = mock_dependencies(&[]);
        let create_info = mock_info("creator", &[]);

        let msg = ExecuteMsg::StartGame {
            opponent: Addr::unchecked("opponent"),
            first_move: GameMove::Paper,
        };

        // should succeed
        let res = execute(deps.as_mut(), mock_env(), create_info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn cant_start_game_if_blacklisted() {
        let mut deps = mock_dependencies(&[]);
        let creator = mock_info("creator", &[]);
        let bad_user = mock_info("bad_user", &[]);

        // blacklist "bad_user"
        instantiate(
            deps.as_mut(),
            mock_env(),
            creator.clone(),
            InstantiateMsg {
                admin: Some(creator.sender.to_string()),
            },
        )
        .unwrap();

        let msg = ExecuteMsg::AddBlacklisted {
            addr: bad_user.sender.clone(),
        };
        execute(deps.as_mut(), mock_env(), creator.clone(), msg).unwrap();

        // make "bad_user" try make a game
        let msg = ExecuteMsg::StartGame {
            opponent: creator.sender,
            first_move: GameMove::Paper,
        };
        let res = execute(deps.as_mut(), mock_env(), bad_user, msg).unwrap_err();
        assert_eq!(ContractError::Blacklisted {}, res);
    }

    #[test]
    fn start_game_returns_correct_attributes() {
        let mut deps = mock_dependencies(&[]);
        let create_info = mock_info("creator", &[]);

        let msg = ExecuteMsg::StartGame {
            opponent: Addr::unchecked("anyone"),
            first_move: GameMove::Scissors,
        };

        let res = execute(deps.as_mut(), mock_env(), create_info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("method", "start_game"),
                ("host", "creator"),
                ("opponent", "anyone"),
                ("host_move", "scissors")
            ]
        );
    }

    #[test]
    fn multiple_players_can_play_at_once() {
        let mut deps = mock_dependencies(&[]);
        let host1 = mock_info("creator", &[]);
        let host2 = mock_info("creator2", &[]);

        let msg = ExecuteMsg::StartGame {
            opponent: Addr::unchecked("anyone"),
            first_move: GameMove::Rock,
        };

        // both hosts should be able to create a game
        let res = execute(deps.as_mut(), mock_env(), host1, msg.clone()).unwrap();
        assert_eq!(0, res.messages.len());

        let res = execute(deps.as_mut(), mock_env(), host2, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn cant_respond_to_none_match() {
        let mut deps = mock_dependencies(&[]);
        let host = mock_info("host", &[]);
        let responder = mock_info("responder", &[]);

        let msg = ExecuteMsg::Respond {
            host: host.sender,
            response_move: GameMove::Rock,
        };

        let res = execute(deps.as_mut(), mock_env(), responder, msg).unwrap_err();
        assert_eq!(ContractError::NoGame {}, res);
    }

    #[test]
    fn can_respond_to_match() {
        let mut deps = mock_dependencies(&[]);
        let host = mock_info("host", &[]);
        let responder = mock_info("responder", &[]);

        // create match
        let msg = ExecuteMsg::StartGame {
            first_move: GameMove::Paper,
            opponent: responder.sender.clone(),
        };
        execute(deps.as_mut(), mock_env(), host.clone(), msg).unwrap();

        // respond to match
        let msg = ExecuteMsg::Respond {
            host: host.sender,
            response_move: GameMove::Scissors,
        };

        let res = execute(deps.as_mut(), mock_env(), responder, msg).unwrap();
        assert!(res.messages.is_empty());
    }

    #[test]
    fn deletes_match_on_response() {
        let mut deps = mock_dependencies(&[]);
        let host = mock_info("host", &[]);
        let responder = mock_info("responder", &[]);

        // create match
        let msg = ExecuteMsg::StartGame {
            first_move: GameMove::Paper,
            opponent: responder.sender.clone(),
        };
        execute(deps.as_mut(), mock_env(), host.clone(), msg).unwrap();

        // respond to match
        let msg = ExecuteMsg::Respond {
            host: host.sender.clone(),
            response_move: GameMove::Scissors,
        };
        execute(deps.as_mut(), mock_env(), responder.clone(), msg).unwrap();

        // both host and opponent should have no matches
        assert!(from_binary::<HostMatchesResponse>(
            &query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetHostMatches {
                    host_address: host.sender
                }
            )
            .unwrap()
        )
        .unwrap()
        .matches
        .is_empty());
        assert!(from_binary::<OpponentMatchesResponse>(
            &query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::GetOpponentMatches {
                    opponent_address: responder.sender
                }
            )
            .unwrap()
        )
        .unwrap()
        .matches
        .is_empty());
    }

    #[test]
    fn respond_returns_correct_attributes() {
        let mut deps = mock_dependencies(&[]);
        let host = mock_info("host", &[]);
        let responder = mock_info("responder", &[]);

        let mut validate_winner =
            |host_move: GameMove, opponent_move: GameMove, correct_winner: &str| {
                // create match
                let msg = ExecuteMsg::StartGame {
                    first_move: host_move,
                    opponent: responder.sender.clone(),
                };
                execute(deps.as_mut(), mock_env(), host.clone(), msg).unwrap();

                // respond to match
                let msg = ExecuteMsg::Respond {
                    host: host.sender.clone(),
                    response_move: opponent_move,
                };
                let res = execute(deps.as_mut(), mock_env(), responder.clone(), msg).unwrap();

                assert_eq!(
                    vec![
                        ("method", "response"),
                        ("host", host.sender.as_str()),
                        ("opponent", responder.sender.as_str()),
                        ("winner", correct_winner)
                    ],
                    res.attributes
                );
            };

        // paper <-> scissors
        validate_winner(GameMove::Paper, GameMove::Scissors, "opponent");
        validate_winner(GameMove::Scissors, GameMove::Paper, "host");

        // scissors <-> rock
        validate_winner(GameMove::Scissors, GameMove::Rock, "opponent");
        validate_winner(GameMove::Rock, GameMove::Scissors, "host");

        // rock <-> paper
        validate_winner(GameMove::Rock, GameMove::Paper, "opponent");
        validate_winner(GameMove::Paper, GameMove::Rock, "host");

        // ties
        validate_winner(GameMove::Paper, GameMove::Paper, "tie");
        validate_winner(GameMove::Scissors, GameMove::Scissors, "tie");
        validate_winner(GameMove::Rock, GameMove::Rock, "tie");
    }

    #[test]
    fn cant_update_admin_if_not_admin() {
        let mut deps = mock_dependencies(&[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            InstantiateMsg {
                admin: Some("creator".to_string()),
            },
        )
        .unwrap();

        let msg = ExecuteMsg::UpdateAdmin {
            new_admin: Some(Addr::unchecked("badactor")),
        };

        let res = execute(deps.as_mut(), mock_env(), mock_info("badactor", &[]), msg).unwrap_err();

        assert_eq!(ContractError::Admin(AdminError::NotAdmin {}), res);
    }

    #[test]
    fn can_update_admin() {
        let mut deps = mock_dependencies(&[]);

        let old_admin = Addr::unchecked("old_admin");
        let new_admin = Addr::unchecked("new_admin");

        let msg = ExecuteMsg::UpdateAdmin {
            new_admin: Some(new_admin.clone()),
        };

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("old_admin", &[]),
            InstantiateMsg {
                admin: Some(old_admin.to_string()),
            },
        )
        .unwrap();

        // should succeed
        let res = execute(deps.as_mut(), mock_env(), mock_info("old_admin", &[]), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // should have new admin
        let msg = QueryMsg::GetAdmin {};
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let value = from_binary::<AdminResponse>(&res).unwrap();

        assert_eq!(new_admin, Addr::unchecked(value.admin.unwrap()));
    }

    #[test]
    fn get_host_matches_returns_correct_matches() {
        let mut deps = mock_dependencies(&[]);

        let player1 = Addr::unchecked("player1");
        let player2 = Addr::unchecked("player2");
        let player3 = Addr::unchecked("player3");

        let mut save_match = |host: &Addr, opponent: &Addr, host_move: GameMove| {
            MATCHES.save(
                &mut deps.storage,
                (host, opponent),
                &Match {
                    host: host.clone(),
                    opponent: opponent.clone(),
                    host_move,
                    opponent_move: None,
                    game_result: None,
                },
            )
        };

        // save some matches
        save_match(&player1, &player2, GameMove::Paper).unwrap();
        save_match(&player2, &player3, GameMove::Scissors).unwrap();
        save_match(&player2, &player1, GameMove::Scissors).unwrap();
        save_match(&player1, &player3, GameMove::Rock).unwrap();

        // get matches
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetHostMatches {
                host_address: player1.clone(),
            },
        )
        .unwrap();
        let value = from_binary::<HostMatchesResponse>(&res).unwrap();

        assert_eq!(
            vec![
                Match {
                    host: player1.clone(),
                    opponent: player2.clone(),
                    host_move: GameMove::Paper,
                    game_result: None,
                    opponent_move: None,
                },
                Match {
                    host: player1.clone(),
                    opponent: player3.clone(),
                    host_move: GameMove::Rock,
                    game_result: None,
                    opponent_move: None,
                }
            ],
            value.matches
        )
    }

    #[test]
    fn get_opponent_matches_returns_correct_matches() {
        let mut deps = mock_dependencies(&[]);

        let player1 = Addr::unchecked("player1");
        let player2 = Addr::unchecked("player2");
        let player3 = Addr::unchecked("player3");

        let mut save_match = |host: &Addr, opponent: &Addr, host_move: GameMove| {
            MATCHES.save(
                &mut deps.storage,
                (host, opponent),
                &Match {
                    host: host.clone(),
                    opponent: opponent.clone(),
                    host_move,
                    opponent_move: None,
                    game_result: None,
                },
            )
        };

        // save some matches
        save_match(&player1, &player2, GameMove::Paper).unwrap();
        save_match(&player2, &player3, GameMove::Scissors).unwrap();
        save_match(&player2, &player1, GameMove::Scissors).unwrap();
        save_match(&player1, &player3, GameMove::Rock).unwrap();

        // get matches
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetOpponentMatches {
                opponent_address: player3.clone(),
            },
        )
        .unwrap();
        let value = from_binary::<OpponentMatchesResponse>(&res).unwrap();

        assert_eq!(
            vec![
                Match {
                    host: player1.clone(),
                    opponent: player3.clone(),
                    host_move: GameMove::Rock,
                    game_result: None,
                    opponent_move: None,
                },
                Match {
                    host: player2.clone(),
                    opponent: player3.clone(),
                    host_move: GameMove::Scissors,
                    game_result: None,
                    opponent_move: None,
                }
            ],
            value.matches
        )
    }

    #[test]
    fn get_admin_returns_correct_admin() {
        let mut deps = mock_dependencies(&[]);

        let admin_key = String::from("admin1");

        let msg = InstantiateMsg {
            admin: Some(admin_key.clone()),
        };
        let info = mock_info("creator", &coins(1000, "earth"));

        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetAdmin {}).unwrap();
        let value = from_binary::<AdminResponse>(&res).unwrap();

        assert_eq!(Some(admin_key), value.admin);
    }
}
