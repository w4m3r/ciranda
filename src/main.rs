use std::fmt::Display;
use std::io;
use std::io::Write;
use std::str::FromStr;

use arboard::Clipboard;
use dialoguer::{Input, MultiSelect, Password, Select};

use ciranda::{
    Argon2Profile, CharacterSet, CharacterSets, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH,
    PasswordSettings, enhance,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn prompt<T: Clone + ToString + FromStr>(label: &str) -> T
where
    <T as FromStr>::Err: Display,
{
    Input::new()
        .with_prompt(label)
        .interact()
        .expect("failed to read input")
}

fn prompt_pass_len() -> u32 {
    Input::<u32>::new()
        .with_prompt("length")
        .validate_with(|value: &u32| {
            if *value < MIN_PASSWORD_LENGTH {
                Err(format!("length must be at least {MIN_PASSWORD_LENGTH}"))
            } else if *value > MAX_PASSWORD_LENGTH {
                Err(format!("length must be at most {MAX_PASSWORD_LENGTH}"))
            } else {
                Ok(())
            }
        })
        .interact()
        .expect("failed to read input")
}

fn prompt_seed() -> String {
    loop {
        let seed = Password::new()
            .with_prompt("seed")
            .interact()
            .expect("failed to read input");
        let confirm_seed = Password::new()
            .with_prompt("confirm seed")
            .interact()
            .expect("failed to read input");

        if seed == confirm_seed {
            return seed;
        }

        eprintln!("Seed entries did not match. Please try again.");
    }
}

fn prompt_profile() -> Argon2Profile {
    let profiles = Argon2Profile::ALL;
    let options: Vec<String> = profiles
        .iter()
        .map(|profile| format!("{} ({})", profile.label(), profile.description()))
        .collect();
    let default = profiles
        .iter()
        .position(|profile| *profile == Argon2Profile::Standard)
        .expect("standard profile missing");
    let selection = Select::new()
        .with_prompt("Argon2 profile")
        .items(&options)
        .default(default)
        .interact()
        .expect("failed to read input");

    profiles[selection]
}

fn prompt_character_sets() -> CharacterSets {
    let character_sets = CharacterSet::ALL;
    let options: Vec<(&str, bool)> = character_sets
        .iter()
        .map(|character_set| (character_set.description(), true))
        .collect();

    loop {
        let selections = MultiSelect::new()
            .with_prompt("character sets")
            .items_checked(options.iter().copied())
            .interact()
            .expect("failed to read input");

        let character_sets = character_sets.iter().enumerate().fold(
            CharacterSets::new(false, false, false, false),
            |selected_sets, (index, character_set)| {
                selected_sets.with(*character_set, selections.contains(&index))
            },
        );

        if character_sets != CharacterSets::new(false, false, false, false) {
            return character_sets;
        }

        eprintln!("At least one character set must be selected. Please try again.");
    }
}

fn main() {
    eprintln!("Ciranda v{VERSION}");

    let seed = prompt_seed();
    let context: String = prompt("context");
    let pass_len = prompt_pass_len();
    let character_sets = prompt_character_sets();
    let password_settings = PasswordSettings::new(pass_len, character_sets);
    let profile = prompt_profile();
    let settings = profile.settings();

    let password = enhance(
        seed.as_bytes(),
        context.as_bytes(),
        &password_settings,
        &settings,
    );

    let mut clipboard = Clipboard::new().expect("failed to access clipboard");
    clipboard
        .set_text(&password)
        .expect("failed to copy to clipboard");

    print!("Password copied to clipboard. Press anything to exit");
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .expect("failed to read input");
}
