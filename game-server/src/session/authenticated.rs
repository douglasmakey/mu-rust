use crate::{session::SessionState, state::GameState};
use anyhow::Result;
use mu_game::{
    character::{Character, CharacterName, HeroState},
    iam::AccountId,
};
use mu_protocol::{packet::RawPacket, protocol_constants::{C1, C3}};
use mu_runtime::PacketStream;
use std::sync::Arc;
use tokio_util::bytes::{BufMut, BytesMut};
use tracing::{debug, warn};

pub(crate) async fn handle(
    stream: &mut PacketStream,
    packet: RawPacket,
    state: &Arc<GameState>,
    account_id: AccountId,
) -> Result<SessionState> {
    let (code, sub_code) = packet.header_codes();
    match (code, sub_code) {
        (Some(0xF3), Some(0x00)) => handle_character_list(stream, state, account_id).await,
        (Some(0xF3), Some(0x03)) => {
            handle_select_character(stream, packet, state, account_id).await
        }
        _ => {
            warn!(code = ?code, sub = ?sub_code, "unhandled packet in Authenticated state — ignoring");
            Ok(SessionState::Authenticated { account_id })
        }
    }
}

async fn handle_character_list(
    stream: &mut PacketStream,
    state: &GameState,
    account_id: AccountId,
) -> Result<SessionState> {
    let response = match state
        .character_service
        .find_all_by_account_id(account_id)
        .await
    {
        Ok(characters) => build_character_list(&characters),
        Err(e) => {
            warn!(account_id = %account_id.0, error = %e, "failed to load character list, sending empty");
            build_character_list(&[])
        }
    };

    stream.send(response).await?;
    Ok(SessionState::Authenticated { account_id })
}

async fn handle_select_character(
    stream: &mut PacketStream,
    packet: RawPacket,
    state: &Arc<GameState>,
    account_id: AccountId,
) -> Result<SessionState> {
    let data = packet.as_slice();
    // Name field: bytes [4..14], null-padded, strip at first 0x00
    let name_bytes = &data[4..14];
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(10);
    let name_str = match std::str::from_utf8(&name_bytes[..end]) {
        Ok(s) => s,
        Err(_) => {
            warn!(account_id = %account_id.0, "select character: invalid UTF-8 in name");
            return Ok(SessionState::Authenticated { account_id });
        }
    };

    let char_name = match CharacterName::new(name_str) {
        Ok(n) => n,
        Err(_) => {
            warn!(account_id = %account_id.0, name = name_str, "select character: invalid name");
            return Ok(SessionState::Authenticated { account_id });
        }
    };

    let character = match state
        .character_service
        .select_character(account_id, &char_name)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!(account_id = %account_id.0, error = %e, "select character failed");
            return Ok(SessionState::Authenticated { account_id });
        }
    };

    stream.send(build_character_stats(&character)).await?;
    stream.send(build_map_changed(&character)).await?;

    debug!(account_id = %account_id.0, character = character.name.as_str(), "character selected");
    Ok(SessionState::InGame {
        account_id,
        character,
    })
}

/// C3-F3-03 CharacterInformation (72 bytes) — Season 6
///
/// Sent after character select; causes the client to enter the game world.
///
/// Layout (all multi-byte values are little-endian unless noted):
///   [0]      C3 (packet type)
///   [1]      72 (total length)
///   [2]      0xF3
///   [3]      0x03
///   [4]      PositionX
///   [5]      PositionY
///   [6-7]    MapId (u16 LE)
///   [8-15]   CurrentExperience (u64 BE)
///   [16-23]  ExperienceForNextLevel (u64 BE)
///   [24-25]  LevelUpPoints
///   [26-27]  Strength
///   [28-29]  Agility
///   [30-31]  Vitality
///   [32-33]  Energy
///   [34-35]  CurrentHealth
///   [36-37]  MaximumHealth
///   [38-39]  CurrentMana
///   [40-41]  MaximumMana
///   [42-43]  CurrentShield
///   [44-45]  MaximumShield
///   [46-47]  CurrentAbility
///   [48-49]  MaximumAbility
///   [50-51]  (padding)
///   [52-55]  Money (u32 LE)
///   [56]     HeroState
///   [57]     Status
///   [58-59]  UsedFruitPoints
///   [60-61]  MaxFruitPoints
///   [62-63]  Leadership
///   [64-65]  UsedNegativeFruitPoints
///   [66-67]  MaxNegativeFruitPoints
///   [68]     InventoryExtensions
///   [69-71]  (padding)
fn build_character_stats(character: &Character) -> RawPacket {
    let mut buf = BytesMut::with_capacity(72);
    // Header
    buf.put_u8(C3);
    buf.put_u8(72);
    buf.put_u8(0xF3);
    buf.put_u8(0x03);
    // Position + Map
    buf.put_u8(character.spawn.position.x); // [4]
    buf.put_u8(character.spawn.position.y); // [5]
    buf.put_u16_le(character.spawn.map_id.0); // [6-7]
    // Experience (big-endian)
    buf.put_u64(0); // [8-15]  CurrentExperience
    buf.put_u64(0); // [16-23] ExperienceForNextLevel
    // Stats (all zeroed — no stat system yet)
    buf.put_u16_le(0); // [24-25] LevelUpPoints
    buf.put_u16_le(0); // [26-27] Strength
    buf.put_u16_le(0); // [28-29] Agility
    buf.put_u16_le(0); // [30-31] Vitality
    buf.put_u16_le(0); // [32-33] Energy
    buf.put_u16_le(100); // [34-35] CurrentHealth
    buf.put_u16_le(100); // [36-37] MaximumHealth
    buf.put_u16_le(50); // [38-39] CurrentMana
    buf.put_u16_le(50); // [40-41] MaximumMana
    buf.put_u16_le(0); // [42-43] CurrentShield
    buf.put_u16_le(0); // [44-45] MaximumShield
    buf.put_u16_le(0); // [46-47] CurrentAbility
    buf.put_u16_le(0); // [48-49] MaximumAbility
    buf.put_u16_le(0); // [50-51] padding
    buf.put_u32_le(0); // [52-55] Money
    buf.put_u8(hero_state_wire(character.hero_state)); // [56]
    buf.put_u8(0); // [57] Status (0 = Normal)
    buf.put_u16_le(0); // [58-59] UsedFruitPoints
    buf.put_u16_le(0); // [60-61] MaxFruitPoints
    buf.put_u16_le(0); // [62-63] Leadership
    buf.put_u16_le(0); // [64-65] UsedNegativeFruitPoints
    buf.put_u16_le(0); // [66-67] MaxNegativeFruitPoints
    buf.put_u8(0); // [68] InventoryExtensions
    buf.put_u8(0); // [69] padding
    buf.put_u8(0); // [70] padding
    buf.put_u8(0); // [71] padding
    RawPacket::try_new(buf.freeze()).expect("character information packet is always valid")
}

/// Maps our domain HeroState to the wire byte value used by the Season 6 protocol.
///
/// OpenMU wire values: New=0, Hero=1, LightHero=2, Normal=3,
///                     PlayerKillWarning=4, PlayerKiller1=5, PlayerKiller2=6
fn hero_state_wire(state: HeroState) -> u8 {
    match state {
        HeroState::Normal => 3,
        HeroState::Hero => 1,
        HeroState::LightsideHero => 2,
        HeroState::PlayerKiller1 => 5,
        HeroState::PlayerKiller2 => 6,
    }
}

/// C3-1C MapChanged075 (8 bytes)
///
/// Sent after CharacterInformation to place the client on the correct map.
///
///   [0]   C3
///   [1]   8 (length)
///   [2]   0x1C
///   [3]   IsMapChange = 0x01 (true = full map switch, removes all scope objects)
///   [4]   MapNumber (u8)
///   [5]   PositionX
///   [6]   PositionY
///   [7]   Rotation = 0
fn build_map_changed(character: &Character) -> RawPacket {
    let mut buf = BytesMut::with_capacity(8);
    buf.put_u8(C3);
    buf.put_u8(8);
    buf.put_u8(0x1C);
    buf.put_u8(0x01); // IsMapChange = true
    // MapNumber: Season 6 MapChanged075 uses u8. Warn and clamp if somehow > 255.
    let map_num = u8::try_from(character.spawn.map_id.0).unwrap_or_else(|_| {
        warn!(map_id = character.spawn.map_id.0, "map_id exceeds u8 range; clamping to 255");
        255
    });
    buf.put_u8(map_num); // MapNumber (u8 for 075 format)
    buf.put_u8(character.spawn.position.x);
    buf.put_u8(character.spawn.position.y);
    buf.put_u8(0x00); // Rotation
    RawPacket::try_new(buf.freeze()).expect("map changed packet is always valid")
}

/// Builds the C1-F3-00 `CharacterListExtended` packet (Season 6).
///
/// Header (8 bytes):
///   [C1][len][0xF3][0x00][UnlockFlags][MoveCnt][CharacterCount][IsVaultExtended]
///
/// Per-character entry (44 bytes):
///   [0]     SlotIndex
///   [1..10] Name (10 bytes, null-padded)
///   [11]    padding (null, so Level lands at index 12)
///   [12..13] Level (u16 LE)
///   [14]    Status flags (bits 0-3: CharacterStatus, bit 4: IsItemBlockActive)
///   [15..41] Appearance (27 bytes):
///              [0]    CharacterClass number
///              [1]    Pose flags
///              [2..24] Equipment slots (7× ShinyItem 3 bytes + 2× UnshinyItem 2 bytes)
///   [42]    GuildPosition (0xFF = not a member)
///   [43]    padding
pub fn build_character_list(characters: &[Character]) -> RawPacket {
    debug!(count = characters.len(), "building character list");
    const ENTRY_SIZE: usize = 44;
    let count = characters.len() as u8;
    let total_len = 8 + count as usize * ENTRY_SIZE;

    let mut buf = BytesMut::with_capacity(total_len);

    // Header (8 bytes)
    buf.put_u8(C1);
    buf.put_u8(total_len as u8);
    buf.put_u8(0xF3);
    buf.put_u8(0x00);
    buf.put_u8(0x00); // [4] UnlockFlags  — no special classes unlocked
    buf.put_u8(0x00); // [5] MoveCnt
    buf.put_u8(count); // [6] CharacterCount
    buf.put_u8(0x00); // [7] IsVaultExtended

    for ch in characters {
        // [0] SlotIndex
        buf.put_u8(ch.slot.get());

        // [1..10] Name, 10 bytes null-padded
        let mut name_buf = [0u8; 10];
        let b = ch.name.as_str().as_bytes();
        let copy_len = b.len().min(10);
        name_buf[..copy_len].copy_from_slice(&b[..copy_len]);
        buf.put_slice(&name_buf);

        // [11] padding — aligns Level to index 12
        buf.put_u8(0x00);

        // [12..13] Level, little-endian
        buf.put_u16_le(ch.level.get());

        // [14] Status flags: lower nibble = CharacterStatus (0=Normal), bit4 = IsItemBlockActive
        buf.put_u8(0x00);

        // [15..41] Appearance (27 bytes)
        // [15] CharacterClass number
        buf.put_u8(ch.class as u8);
        // [16] Pose (0 = standing; bit4 = full ancient set; bit5 = GM)
        buf.put_u8(0x00);
        // [17..41] Equipment slots — all empty
        // 7× ShinyItem (3 bytes each): Group=0xF, Number=0xFFF → 0xFF, 0xFF, 0x00
        for _ in 0..7 {
            buf.put_u8(0xFF);
            buf.put_u8(0xFF);
            buf.put_u8(0x00);
        }
        // 2× UnshinyItem (2 bytes each): Group=0xF, Number=0xFFF → 0xFF, 0xFF
        for _ in 0..2 {
            buf.put_u8(0xFF);
            buf.put_u8(0xFF);
        }

        // [42] GuildPosition (0xFF = not a member / Undefined)
        buf.put_u8(0xFF);

        // [43] padding
        buf.put_u8(0x00);
    }

    RawPacket::try_new(buf.freeze()).expect("character list packet is always valid")
}
