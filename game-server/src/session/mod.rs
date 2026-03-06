mod authenticated;
mod connected;

use crate::state::GameState;
use anyhow::Result;
use mu_game::{character::Character, iam::AccountId};
use mu_runtime::PacketStream;
use std::{net::SocketAddr, sync::Arc};
use tracing::{debug, info, warn};

pub enum SessionState {
    Connected,
    Authenticated {
        account_id: AccountId,
    },
    // For the future
    InGame {
        account_id: AccountId,
        character: Character,
    },
}

/// Drive the session state machine until the client disconnects or an error occurs.
pub async fn run(mut stream: PacketStream, peer: SocketAddr, state: Arc<GameState>) -> Result<()> {
    let mut logged_account: Option<AccountId> = None;
    let result = run_loop(&mut stream, &peer, &state, &mut logged_account).await;

    if let Some(account_id) = logged_account {
        state.auth_service.logout(account_id).await;
    }

    info!(%peer, account_id = ?logged_account, "session closed");
    result
}

async fn run_loop(
    stream: &mut PacketStream,
    peer: &SocketAddr,
    state: &Arc<GameState>,
    logged_account: &mut Option<AccountId>,
) -> Result<()> {
    let mut session = SessionState::Connected;
    loop {
        let packet = match stream.recv().await {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                warn!(%peer, error = %e, "packet error, closing session");
                break;
            }
            None => {
                debug!(%peer, "client disconnected");
                break;
            }
        };

        session = match session {
            SessionState::Connected => connected::handle(stream, packet, state).await?,
            SessionState::Authenticated { account_id } => {
                authenticated::handle(stream, packet, state, account_id).await?
            }
            SessionState::InGame {
                account_id,
                character,
            } => {
                let (code, sub_code) = packet.header_codes();
                debug!(
                    account_id = %account_id.0,
                    character = character.name.as_str(),
                    code = ?code,
                    sub_code = ?sub_code,
                    "unhandled in-game packet — future phase"
                );
                SessionState::InGame {
                    account_id,
                    character,
                }
            }
        };

        // Track account_id for cleanup on disconnect.
        match &session {
            SessionState::Authenticated { account_id } => *logged_account = Some(*account_id),
            SessionState::InGame { account_id, .. } => *logged_account = Some(*account_id),
            SessionState::Connected => {}
        }
    }

    Ok(())
}
