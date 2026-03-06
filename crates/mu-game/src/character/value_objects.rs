use crate::character::CharacterError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CharacterId(pub i64);

/// A validated character name — max 10 bytes, matches the wire field size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CharacterName(String);

impl CharacterName {
    pub const MAX_LEN: usize = 10;

    pub fn new(raw: &str) -> Result<Self, CharacterError> {
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(CharacterError::InvalidName);
        }
        Ok(Self(raw.to_string()))
    }

    /// Construct from a trusted source (e.g. DB row already validated by DB constraints).
    pub fn from_trusted(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterSlot(u8);

impl CharacterSlot {
    pub fn new(slot: u8) -> Result<Self, CharacterError> {
        if slot > 4 {
            return Err(CharacterError::MaxSlotsReached);
        }
        Ok(Self(slot))
    }

    pub fn from_db(slot: i16) -> Self {
        Self(slot.clamp(0, 4) as u8)
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CharacterClass {
    DarkWizard = 0,
    DarkKnight = 1,
    FairyElf = 2,
    MagicGladiator = 3,
    DarkLord = 4,
    SoulMaster = 16,
    BladeKnight = 17,
    MuseElf = 18,
}

impl TryFrom<i16> for CharacterClass {
    type Error = ();

    fn try_from(v: i16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::DarkWizard),
            1 => Ok(Self::DarkKnight),
            2 => Ok(Self::FairyElf),
            3 => Ok(Self::MagicGladiator),
            4 => Ok(Self::DarkLord),
            16 => Ok(Self::SoulMaster),
            17 => Ok(Self::BladeKnight),
            18 => Ok(Self::MuseElf),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CharacterLevel(u16);

impl CharacterLevel {
    pub const MIN: u16 = 1;
    pub const MAX: u16 = 400;

    pub fn new(level: u16) -> Result<Self, CharacterError> {
        if !(Self::MIN..=Self::MAX).contains(&level) {
            return Err(CharacterError::LevelOutOfRange {
                min: Self::MIN as i64,
                max: Self::MAX as i64,
                actual: level as i64,
            });
        }
        Ok(Self(level))
    }

    /// Construct from a trusted source, clamping to valid range.
    pub fn from_db(level: i16) -> Self {
        Self(level.clamp(Self::MIN as i16, Self::MAX as i16) as u16)
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub x: u8,
    pub y: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapId(pub u16);

impl MapId {
    pub fn from_db(id: i16) -> Self {
        Self(id as u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnPoint {
    pub map_id: MapId,
    pub position: Position,
}

/// Hero/PK state of a character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeroState {
    Normal = 0,
    Hero = 1,
    LightsideHero = 2,
    PlayerKiller1 = 3,
    PlayerKiller2 = 4,
}

impl TryFrom<i16> for HeroState {
    type Error = ();

    fn try_from(v: i16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Hero),
            2 => Ok(Self::LightsideHero),
            3 => Ok(Self::PlayerKiller1),
            4 => Ok(Self::PlayerKiller2),
            _ => Err(()),
        }
    }
}
