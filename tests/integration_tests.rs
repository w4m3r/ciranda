use ciranda::{Argon2Profile, CharacterSets, PasswordSettings, enhance};

#[test]
fn enhance_produces_known_password() {
    let settings = Argon2Profile::Development.settings();
    let password_settings = PasswordSettings::new(32, CharacterSets::ALL);
    let password = enhance(b"seed", b"context", &password_settings, &settings);
    assert_eq!(password, "n&C7WAOp5vg!mx0vLHLhu^eDxd1PDQgK");
}

#[test]
fn enhance_is_deterministic() {
    let settings = Argon2Profile::Development.settings();
    let password_settings = PasswordSettings::new(32, CharacterSets::ALL);
    let password1 = enhance(b"seed", b"context", &password_settings, &settings);
    let password2 = enhance(b"seed", b"context", &password_settings, &settings);
    assert_eq!(password1, password2);
}

#[test]
fn enhance_includes_each_character_group() {
    let settings = Argon2Profile::Development.settings();
    let password_settings = PasswordSettings::new(32, CharacterSets::ALL);
    let password = enhance(b"seed", b"context", &password_settings, &settings);
    assert!(password.chars().any(|c| c.is_ascii_uppercase()));
    assert!(password.chars().any(|c| c.is_ascii_lowercase()));
    assert!(password.chars().any(|c| c.is_ascii_digit()));
    assert!(password.chars().any(|c| "!@#$%^&*".contains(c)));
}

#[test]
fn enhance_respects_selected_character_sets() {
    let settings = Argon2Profile::Development.settings();
    let password_settings = PasswordSettings::new(32, CharacterSets::new(false, true, true, false));
    let password = enhance(b"seed", b"context", &password_settings, &settings);

    assert!(password.chars().any(|c| c.is_ascii_lowercase()));
    assert!(password.chars().any(|c| c.is_ascii_digit()));
    assert!(!password.chars().any(|c| c.is_ascii_uppercase()));
    assert!(!password.chars().any(|c| "!@#$%^&*".contains(c)));
}
