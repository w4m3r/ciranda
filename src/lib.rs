#![doc = include_str!("../README.md")]

mod kdf;
mod password_construction;

pub const MIN_PASSWORD_LENGTH: u32 = 4;
pub const MAX_PASSWORD_LENGTH: u32 = 128;

const DEVELOPMENT_M_COST: u32 = 8;
const DEVELOPMENT_T_COST: u32 = 1;
const DEVELOPMENT_P_COST: u32 = 1;
const STANDARD_M_COST: u32 = 65_536;
const STANDARD_T_COST: u32 = 3;
const STANDARD_P_COST: u32 = 4;
const HARDENED_M_COST: u32 = 2_097_152;
const HARDENED_T_COST: u32 = 1;
const HARDENED_P_COST: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Character groups available to the deterministic password-construction stage.
///
/// Selected groups define the output alphabet. Each selected group contributes
/// at least one character, and unselected groups are excluded entirely.
pub struct CharacterSets {
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub special: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A single selectable password character group.
///
/// The order in [`CharacterSet::ALL`] is the canonical bucket-construction
/// order used by the password-construction stage.
pub enum CharacterSet {
    Uppercase,
    Lowercase,
    Digits,
    Special,
}

impl CharacterSet {
    pub const ALL: [Self; 4] = [
        Self::Uppercase,
        Self::Lowercase,
        Self::Digits,
        Self::Special,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Uppercase => "Uppercase",
            Self::Lowercase => "Lowercase",
            Self::Digits => "Digits",
            Self::Special => "Special",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Uppercase => "uppercase letters (A-Z)",
            Self::Lowercase => "lowercase letters (a-z)",
            Self::Digits => "digits (0-9)",
            Self::Special => "special characters (!@#$%^&*)",
        }
    }
}

impl CharacterSets {
    pub const ALL: Self = Self::new(true, true, true, true);

    pub const fn new(uppercase: bool, lowercase: bool, digits: bool, special: bool) -> Self {
        Self {
            uppercase,
            lowercase,
            digits,
            special,
        }
    }

    pub(crate) const fn selected_count(self) -> usize {
        self.uppercase as usize
            + self.lowercase as usize
            + self.digits as usize
            + self.special as usize
    }

    pub fn with(self, character_set: CharacterSet, selected: bool) -> Self {
        match character_set {
            CharacterSet::Uppercase => Self {
                uppercase: selected,
                ..self
            },
            CharacterSet::Lowercase => Self {
                lowercase: selected,
                ..self
            },
            CharacterSet::Digits => Self {
                digits: selected,
                ..self
            },
            CharacterSet::Special => Self {
                special: selected,
                ..self
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Password construction settings.
///
/// The length must be between [`MIN_PASSWORD_LENGTH`] and
/// [`MAX_PASSWORD_LENGTH`]. At least one character group must be selected.
pub struct PasswordSettings {
    pub length: u32,
    pub character_sets: CharacterSets,
}

impl PasswordSettings {
    pub const fn new(length: u32, character_sets: CharacterSets) -> Self {
        Self {
            length,
            character_sets,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Named Argon2id presets for common use cases.
///
/// [`Argon2Profile::Standard`] is inteded for normal interactive use.
/// [`Argon2Profile::Development`] is only for tests, examples, and fast local
/// iteration. [`Argon2Profile::Hardened`] is intended for capable machines that
/// can tolerate substantially higher memory use.
///
/// Profile changes affect the derived password, but they are not the preferred
/// rotation mechanism. Rotate by changing the seed or by versioning the
/// context.
pub enum Argon2Profile {
    Development,
    Standard,
    Hardened,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Settings {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Settings {
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }
}

impl Argon2Profile {
    pub const ALL: [Self; 3] = [Self::Development, Self::Standard, Self::Hardened];

    pub fn label(self) -> &'static str {
        match self {
            Self::Development => "Development",
            Self::Standard => "Standard",
            Self::Hardened => "Hardened",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Development => "8 KiB memory, 1 iteration, 1 lane",
            Self::Standard => "64 MiB memory, 3 iterations, 4 lanes",
            Self::Hardened => "2 GiB memory, 1 iteration, 4 lanes",
        }
    }

    pub fn settings(self) -> Argon2Settings {
        match self {
            Self::Development => {
                Argon2Settings::new(DEVELOPMENT_M_COST, DEVELOPMENT_T_COST, DEVELOPMENT_P_COST)
            }
            Self::Standard => {
                Argon2Settings::new(STANDARD_M_COST, STANDARD_T_COST, STANDARD_P_COST)
            }
            Self::Hardened => {
                Argon2Settings::new(HARDENED_M_COST, HARDENED_T_COST, HARDENED_P_COST)
            }
        }
    }
}

/// Derives a password from a seed and context using Argon2id KDF and BLAKE3 hashing.
///
/// The process:
/// 1. Hash context with BLAKE3 to produce a 16-byte salt
/// 2. Use Argon2id KDF to derive a 64-byte key from the seed and salt
/// 3. Expand the key into deterministic BLAKE3 XOF byte streams
/// 4. Deterministically shuffle character buckets and select one character per bucket
///
/// # Arguments
/// * `seed` - The master password/seed bytes
/// * `context` - Context bytes (e.g., service name) to derive unique passwords
/// * `password_settings` - Password length and selected character sets. For
///   normal use, start with `PasswordSettings::new(length, CharacterSets::ALL)`.
/// * `settings` - Argon2 settings (m_cost, t_cost, p_cost). Output length is fixed internally.
///   For normal use, prefer `Argon2Profile::Standard.settings()`. Reserve
///   `Argon2Profile::Development.settings()` for tests and examples, and use
///   `Argon2Profile::Hardened.settings()` only when the higher memory cost is
///   intentional and acceptable.
/// # Example
///
/// ```
/// use ciranda::{Argon2Profile, CharacterSets, PasswordSettings, enhance};
/// let settings = Argon2Profile::Development.settings();
/// let password_settings = PasswordSettings::new(32, CharacterSets::ALL);
/// let password = enhance(b"seed", b"context", &password_settings, &settings);
/// assert_eq!(password, "n&C7WAOp5vg!mx0vLHLhu^eDxd1PDQgK");
/// ```
pub fn enhance(
    seed: &[u8],
    context: &[u8],
    password_settings: &PasswordSettings,
    settings: &Argon2Settings,
) -> String {
    let salt = kdf::hash_salt(context);
    let key = kdf::derive_key(seed, &salt, settings);
    password_construction::construct_password(&key, password_settings)
}

#[cfg(test)]
mod tests {
    use super::{
        Argon2Profile, DEVELOPMENT_M_COST, DEVELOPMENT_P_COST, DEVELOPMENT_T_COST, HARDENED_M_COST,
        HARDENED_P_COST, HARDENED_T_COST, STANDARD_M_COST, STANDARD_P_COST, STANDARD_T_COST,
    };

    #[test]
    fn argon2_profiles_use_expected_settings() {
        let development = Argon2Profile::Development.settings();
        let standard = Argon2Profile::Standard.settings();
        let hardened = Argon2Profile::Hardened.settings();

        assert_eq!(
            (development.m_cost, development.t_cost, development.p_cost),
            (DEVELOPMENT_M_COST, DEVELOPMENT_T_COST, DEVELOPMENT_P_COST)
        );
        assert_eq!(
            (standard.m_cost, standard.t_cost, standard.p_cost),
            (STANDARD_M_COST, STANDARD_T_COST, STANDARD_P_COST)
        );
        assert_eq!(
            (hardened.m_cost, hardened.t_cost, hardened.p_cost),
            (HARDENED_M_COST, HARDENED_T_COST, HARDENED_P_COST)
        );
    }
}
