use blake3::{Hasher, OutputReader};

use crate::kdf::{KEY_SIZE, Key};
use crate::{CharacterSets, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, PasswordSettings};

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*";
const STREAM_KEY_SIZE: usize = 32;
const SHUFFLE_DOMAIN: &[u8] = b"ciranda:v0:shuffle";
const PICK_DOMAIN: &[u8] = b"ciranda:v0:pick";

struct DeterministicByteStream {
    reader: OutputReader,
    buffer: [u8; STREAM_KEY_SIZE],
    offset: usize,
}

impl DeterministicByteStream {
    fn new(key: &[u8; STREAM_KEY_SIZE], domain: &'static [u8]) -> Self {
        let mut hasher = Hasher::new_keyed(key);
        hasher.update(domain);
        let mut stream = Self {
            reader: hasher.finalize_xof(),
            buffer: [0u8; STREAM_KEY_SIZE],
            offset: STREAM_KEY_SIZE,
        };
        stream.refill();
        stream
    }

    fn refill(&mut self) {
        self.reader.fill(&mut self.buffer);
        self.offset = 0;
    }

    fn next_u8(&mut self) -> u8 {
        if self.offset >= self.buffer.len() {
            self.refill();
        }

        let byte = self.buffer[self.offset];
        self.offset += 1;
        byte
    }
}

fn stream_keys(key: &Key) -> ([u8; STREAM_KEY_SIZE], [u8; STREAM_KEY_SIZE]) {
    let mut shuffle_key = [0u8; STREAM_KEY_SIZE];
    let mut pick_key = [0u8; STREAM_KEY_SIZE];
    shuffle_key.copy_from_slice(&key[..STREAM_KEY_SIZE]);
    pick_key.copy_from_slice(&key[STREAM_KEY_SIZE..KEY_SIZE]);
    (shuffle_key, pick_key)
}

fn uniform_index(stream: &mut DeterministicByteStream, upper_exclusive: usize) -> usize {
    assert!(upper_exclusive > 0, "cannot sample from an empty range");
    if upper_exclusive == 1 {
        return 0;
    }

    let upper = upper_exclusive as u16;
    let source_size = u16::from(u8::MAX) + 1;
    let zone = source_size - (source_size % upper);

    loop {
        let value = u16::from(stream.next_u8());
        if value < zone {
            return (value % upper) as usize;
        }
    }
}

fn selected_character_groups(character_sets: CharacterSets) -> impl Iterator<Item = &'static [u8]> {
    [
        (character_sets.uppercase, UPPERCASE),
        (character_sets.lowercase, LOWERCASE),
        (character_sets.digits, DIGITS),
        (character_sets.special, SPECIAL),
    ]
    .into_iter()
    .filter_map(|(selected, group)| selected.then_some(group))
}

fn selected_alphabet(character_sets: CharacterSets) -> Vec<u8> {
    selected_character_groups(character_sets)
        .flat_map(|group| group.iter().copied())
        .collect()
}

fn validate_settings(settings: &PasswordSettings) {
    assert!(
        settings.character_sets.selected_count() > 0,
        "at least one character group must be selected"
    );
    assert!(
        settings.length >= MIN_PASSWORD_LENGTH,
        "pass_len must be at least {MIN_PASSWORD_LENGTH}"
    );
    assert!(
        settings.length <= MAX_PASSWORD_LENGTH,
        "pass_len must be at most {MAX_PASSWORD_LENGTH}"
    );
    assert!(
        settings.length as usize >= settings.character_sets.selected_count(),
        "pass_len must be at least the number of selected character groups"
    );
}

fn character_buckets<'a>(
    settings: &PasswordSettings,
    selected_alphabet: &'a [u8],
) -> Vec<&'a [u8]> {
    let mut buckets: Vec<&'a [u8]> = selected_character_groups(settings.character_sets).collect();
    buckets.extend(std::iter::repeat_n(
        selected_alphabet,
        settings.length as usize - buckets.len(),
    ));

    buckets
}

/// Construct a deterministic password from the derived key.
pub(crate) fn construct_password(key: &Key, settings: &PasswordSettings) -> String {
    validate_settings(settings);

    let alphabet = selected_alphabet(settings.character_sets);
    let mut buckets = character_buckets(settings, &alphabet);
    let (shuffle_key, pick_key) = stream_keys(key);
    let mut shuffle_stream = DeterministicByteStream::new(&shuffle_key, SHUFFLE_DOMAIN);
    let mut pick_stream = DeterministicByteStream::new(&pick_key, PICK_DOMAIN);

    for i in (1..buckets.len()).rev() {
        let j = uniform_index(&mut shuffle_stream, i + 1);
        buckets.swap(i, j);
    }

    let password: Vec<u8> = buckets
        .into_iter()
        .map(|bucket| bucket[uniform_index(&mut pick_stream, bucket.len())])
        .collect();

    String::from_utf8(password).expect("password alphabet must remain valid ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CHARACTERS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

    fn sample_key() -> Key {
        [
            214, 215, 94, 195, 154, 210, 132, 192, 32, 216, 201, 38, 123, 101, 121, 24, 90, 99, 55,
            172, 98, 1, 7, 141, 23, 177, 78, 16, 33, 224, 11, 46, 196, 174, 141, 3, 7, 67, 239,
            137, 12, 67, 74, 175, 45, 210, 85, 173, 96, 198, 149, 0, 98, 42, 203, 104, 36, 163, 67,
            109, 70, 237, 92, 44,
        ]
    }

    fn other_sample_key() -> Key {
        [
            11, 249, 42, 73, 159, 214, 88, 131, 7, 201, 54, 190, 33, 117, 228, 14, 166, 95, 240,
            61, 182, 27, 143, 76, 209, 18, 250, 104, 57, 171, 36, 198, 121, 12, 233, 68, 145, 30,
            220, 83, 174, 5, 197, 112, 246, 41, 156, 99, 208, 24, 187, 63, 134, 215, 52, 169, 8,
            241, 126, 35, 193, 70, 154, 17,
        ]
    }

    #[test]
    fn construct_password_produces_known_password_for_known_key() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::ALL);
        let password = construct_password(&key, &settings);
        assert_eq!(password, "n&C7WAOp5vg!mx0vLHLhu^eDxd1PDQgK")
    }

    #[test]
    fn construct_password_produces_known_uppercase_digits_password_for_known_key() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::new(true, false, true, false));
        let password = construct_password(&key, &settings);
        assert_eq!(password, "B4AVSN87MF4VJSW8GJMLHDH5I34NN1VV")
    }

    #[test]
    fn construct_password_is_deterministic() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::ALL);
        let result1 = construct_password(&key, &settings);
        let result2 = construct_password(&key, &settings);
        assert_eq!(result1, result2);
    }

    #[test]
    fn construct_password_different_keys_produce_different_outputs() {
        let key1 = sample_key();
        let key2 = other_sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::ALL);
        let result1 = construct_password(&key1, &settings);
        let result2 = construct_password(&key2, &settings);
        assert_ne!(result1, result2);
    }

    #[test]
    fn construct_password_produces_known_passwords_for_representative_lengths() {
        let key = sample_key();

        let cases = [
            (MIN_PASSWORD_LENGTH, "^i2Z"),
            (
                64,
                "n&C7WAOp5vW!mx0v*HLh6feDxdVXDQgK2Pz&xN&UaK8h6o2SZ7vmpeReC6pRIK03",
            ),
            (
                MAX_PASSWORD_LENGTH,
                "n&C7WAOp5vW!mx0vLHLhufeDxdVXDQgKr2Pz&x$8UIK8h6o2SZ7vmpeReC6pHIK03g$RUYyuc5D^$sb*OotWqse1Rd&GXfvAr9LX42E87z$bbdM*B9*2l4v&pfVVCPR&",
            ),
        ];

        for (length, expected) in cases {
            let password =
                construct_password(&key, &PasswordSettings::new(length, CharacterSets::ALL));

            assert_eq!(password, expected);
            assert_eq!(password.len(), length as usize);
        }
    }

    #[test]
    fn construct_password_output_uses_expected_alphabet() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::ALL);
        let result = construct_password(&key, &settings);
        assert!(result.chars().all(|c| ALL_CHARACTERS.contains(&(c as u8))));
    }

    #[test]
    fn construct_password_includes_each_character_group() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::ALL);
        let result = construct_password(&key, &settings);
        assert!(result.chars().any(|c| c.is_ascii_uppercase()));
        assert!(result.chars().any(|c| c.is_ascii_lowercase()));
        assert!(result.chars().any(|c| c.is_ascii_digit()));
        assert!(result.chars().any(|c| SPECIAL.contains(&(c as u8))));
    }

    #[test]
    fn construct_password_uses_only_selected_single_group() {
        let key = sample_key();
        let uppercase = construct_password(
            &key,
            &PasswordSettings::new(16, CharacterSets::new(true, false, false, false)),
        );
        let lowercase = construct_password(
            &key,
            &PasswordSettings::new(16, CharacterSets::new(false, true, false, false)),
        );
        let digits = construct_password(
            &key,
            &PasswordSettings::new(16, CharacterSets::new(false, false, true, false)),
        );
        let special = construct_password(
            &key,
            &PasswordSettings::new(16, CharacterSets::new(false, false, false, true)),
        );

        assert!(uppercase.chars().all(|c| c.is_ascii_uppercase()));
        assert!(lowercase.chars().all(|c| c.is_ascii_lowercase()));
        assert!(digits.chars().all(|c| c.is_ascii_digit()));
        assert!(special.chars().all(|c| SPECIAL.contains(&(c as u8))));
    }

    #[test]
    fn construct_password_includes_each_selected_group_and_excludes_unselected_groups() {
        let key = sample_key();
        let settings = PasswordSettings::new(32, CharacterSets::new(true, false, true, false));
        let result = construct_password(&key, &settings);

        assert!(result.chars().any(|c| c.is_ascii_uppercase()));
        assert!(result.chars().any(|c| c.is_ascii_digit()));
        assert!(!result.chars().any(|c| c.is_ascii_lowercase()));
        assert!(!result.chars().any(|c| SPECIAL.contains(&(c as u8))));
    }

    #[test]
    fn construct_password_different_character_sets_produce_different_outputs() {
        let key = sample_key();
        let all_groups = construct_password(&key, &PasswordSettings::new(32, CharacterSets::ALL));
        let alphanumeric = construct_password(
            &key,
            &PasswordSettings::new(32, CharacterSets::new(true, true, true, false)),
        );

        assert_ne!(all_groups, alphanumeric);
    }

    #[test]
    #[should_panic(expected = "pass_len must be at least")]
    fn construct_password_panics_when_length_is_too_short() {
        let key = sample_key();
        let settings = PasswordSettings::new(MIN_PASSWORD_LENGTH - 1, CharacterSets::ALL);
        let _ = construct_password(&key, &settings);
    }

    #[test]
    #[should_panic(expected = "pass_len must be at most")]
    fn construct_password_panics_when_length_is_too_long() {
        let key = sample_key();
        let settings = PasswordSettings::new(MAX_PASSWORD_LENGTH + 1, CharacterSets::ALL);
        let _ = construct_password(&key, &settings);
    }

    #[test]
    #[should_panic(expected = "at least one character group")]
    fn construct_password_panics_when_no_character_group_is_selected() {
        let key = sample_key();
        let settings = PasswordSettings::new(16, CharacterSets::new(false, false, false, false));
        let _ = construct_password(&key, &settings);
    }
}
