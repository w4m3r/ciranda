use argon2::{Algorithm, Argon2, ParamsBuilder};
use blake3::Hasher;

use crate::Argon2Settings;

const SALT_SIZE: usize = 16;
pub(crate) const KEY_SIZE: usize = 64;
const SALT_DOMAIN: &[u8] = b"ciranda:v0:salt";

pub(crate) type Salt = [u8; SALT_SIZE];
pub(crate) type Key = [u8; KEY_SIZE];

pub(crate) fn hash_salt(context: &[u8]) -> Salt {
    let mut hasher = Hasher::new();
    hasher.update(SALT_DOMAIN);
    hasher.update(context);
    let hash = hasher.finalize();
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&hash.as_bytes()[..SALT_SIZE]);
    salt
}

pub(crate) fn derive_key(seed: &[u8], salt: &Salt, settings: &Argon2Settings) -> Key {
    let params = ParamsBuilder::new()
        .m_cost(settings.m_cost)
        .t_cost(settings.t_cost)
        .p_cost(settings.p_cost)
        .output_len(KEY_SIZE)
        .build()
        .expect("invalid Argon2 settings");
    let argon2 = Argon2::new(Algorithm::Argon2id, Default::default(), params);
    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(seed, salt, &mut key)
        .expect("Argon2 KDF failed");
    key
}

#[cfg(test)]
mod tests {
    use super::{Key, Salt, derive_key, hash_salt};
    use crate::{Argon2Profile, Argon2Settings};

    fn expected_salt_for_context() -> Salt {
        [
            206, 92, 56, 77, 80, 248, 28, 76, 154, 136, 227, 182, 102, 235, 148, 100,
        ]
    }

    fn sample_salt_for_other_context() -> Salt {
        [
            193, 32, 122, 63, 106, 197, 115, 149, 36, 145, 179, 124, 11, 225, 148, 172,
        ]
    }

    fn expected_key_for_seed_and_context() -> Key {
        [
            214, 215, 94, 195, 154, 210, 132, 192, 32, 216, 201, 38, 123, 101, 121, 24, 90, 99, 55,
            172, 98, 1, 7, 141, 23, 177, 78, 16, 33, 224, 11, 46, 196, 174, 141, 3, 7, 67, 239,
            137, 12, 67, 74, 175, 45, 210, 85, 173, 96, 198, 149, 0, 98, 42, 203, 104, 36, 163, 67,
            109, 70, 237, 92, 44,
        ]
    }

    #[test]
    fn hash_salt_produces_known_salt_for_known_context() {
        let salt = hash_salt(b"context");
        assert_eq!(salt, expected_salt_for_context());
    }

    #[test]
    fn hash_salt_produces_different_salts_for_different_contexts() {
        let salt1 = hash_salt(b"context");
        let salt2 = hash_salt(b"context2");
        assert_ne!(salt1, salt2);
        assert_eq!(salt2, sample_salt_for_other_context());
    }

    #[test]
    fn derive_key_produces_known_key_for_known_seed_and_context() {
        let settings = Argon2Profile::Development.settings();
        let context = expected_salt_for_context();
        let key = derive_key(b"seed", &context, &settings);
        assert_eq!(key, expected_key_for_seed_and_context());
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_seeds() {
        let settings = Argon2Profile::Development.settings();
        let context = expected_salt_for_context();
        let key1 = derive_key(b"seed", &context, &settings);
        let key2 = derive_key(b"seed2", &context, &settings);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_contexts() {
        let settings = Argon2Profile::Development.settings();
        let context1 = expected_salt_for_context();
        let context2 = sample_salt_for_other_context();
        let key1 = derive_key(b"seed", &context1, &settings);
        let key2 = derive_key(b"seed", &context2, &settings);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_memory_params() {
        let settings1 = Argon2Settings::new(8, 1, 1);
        let settings2 = Argon2Settings::new(16, 1, 1);
        let salt = expected_salt_for_context();
        let key1 = derive_key(b"seed", &salt, &settings1);
        let key2 = derive_key(b"seed", &salt, &settings2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_time_params() {
        let settings1 = Argon2Settings::new(8, 1, 1);
        let settings2 = Argon2Settings::new(8, 2, 1);
        let salt = expected_salt_for_context();
        let key1 = derive_key(b"seed", &salt, &settings1);
        let key2 = derive_key(b"seed", &salt, &settings2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_parallel_params() {
        let settings1 = Argon2Settings::new(16, 1, 1);
        let settings2 = Argon2Settings::new(16, 1, 2);
        let salt = expected_salt_for_context();
        let key1 = derive_key(b"seed", &salt, &settings1);
        let key2 = derive_key(b"seed", &salt, &settings2);
        assert_ne!(key1, key2);
    }
}
