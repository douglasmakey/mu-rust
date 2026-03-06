use crate::{session::SessionState, state::GameState};
use anyhow::Result;
use mu_game::{
    iam::{AccountId, Username, account::AccountError},
    services::auth::AuthServiceError,
};
use mu_protocol::{
    crypto::xor3::decrypt_xor3, error::ProtocolError, packet::RawPacket, protocol_constants::C1,
};
use mu_runtime::PacketStream;
use std::sync::Arc;
use tokio_util::bytes::{BufMut, BytesMut};
use tracing::{debug, warn};

pub(crate) struct LoginRequest {
    username: Username,
    password: String,
}

impl TryFrom<RawPacket> for LoginRequest {
    type Error = anyhow::Error;

    fn try_from(packet: RawPacket) -> Result<Self> {
        let data = packet.as_slice();
        let raw_username = decrypt_field(&data[4..14])?;
        let raw_password = decrypt_field(&data[14..24])?;
        let username = Username::new(&raw_username).map_err(|_| ProtocolError::Malformed)?;
        Ok(LoginRequest {
            username,
            password: raw_password,
        })
    }
}

pub(crate) async fn handle(
    stream: &mut PacketStream,
    packet: RawPacket,
    state: &Arc<GameState>,
) -> Result<SessionState> {
    let (code, sub_code) = packet.header_codes();
    match (code, sub_code) {
        (Some(0xF1), Some(0x01)) => handle_login(stream, packet, state).await,
        _ => {
            warn!(code = ?code, sub = ?sub_code, "unexpected packet in Connected state — ignoring");
            Ok(SessionState::Connected)
        }
    }
}

async fn handle_login(
    stream: &mut PacketStream,
    packet: RawPacket,
    state: &Arc<GameState>,
) -> Result<SessionState> {
    let request = LoginRequest::try_from(packet)?;
    let login_result = state
        .auth_service
        .login(&request.username, &request.password)
        .await;

    let response = build_login_response(&login_result);
    stream.send(response).await?;

    match login_result {
        Ok(account_id) => {
            debug!(account_id = %account_id.0, "login successful");
            Ok(SessionState::Authenticated { account_id })
        }
        Err(e) => {
            warn!(error = %e, "login failed");
            Ok(SessionState::Connected)
        }
    }
}

fn build_login_response(login_result: &Result<AccountId, AuthServiceError>) -> RawPacket {
    let code = match login_result {
        Ok(_) => 0x01,
        Err(AuthServiceError::InvalidCredentials) => 0x00,
        Err(AuthServiceError::DuplicateSession) => 0x02,
        Err(AuthServiceError::Domain(domain_err)) => match domain_err {
            AccountError::PermanentlyBanned => 0x03,
            AccountError::TemporarilyBanned { .. } => 0x06,
            AccountError::InvalidLoginName => 0x00,
        },
        Err(AuthServiceError::PasswordVerificationFailed) => 0x00,
        Err(AuthServiceError::Infrastructure(_)) => 0x00,
    };

    let mut buf = BytesMut::with_capacity(5);
    buf.put_u8(C1);
    buf.put_u8(0x05);
    buf.put_u8(0xF1);
    buf.put_u8(0x01);
    buf.put_u8(code);
    RawPacket::try_new(buf.freeze()).expect("login response is always valid")
}

/// XOR3-decrypt a 10-byte field and strip the null terminator.
fn decrypt_field(raw: &[u8]) -> Result<String, ProtocolError> {
    let mut buf = raw.to_vec();
    decrypt_xor3(&mut buf);
    // Strip null bytes (null-padded to fixed length).
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end])
        .map(str::to_string)
        .map_err(|_| ProtocolError::Malformed)
}
