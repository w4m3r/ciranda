# Design Overview

Ciranda is a deterministic password generator. Given the same inputs, it
produces the same password.

The design is intentionally split into two stages:

1. enhance the human-entered seed into fixed-size key material
2. construct an exact-length password from that key material

This separation keeps the password-hardening concern distinct from the output
format concern. Argon2id handles the cost of guessing the seed. The password
construction stage handles length, character sets, and deterministic placement.

## Inputs

The CLI prompts for:

- `seed`: the master secret, entered hidden and confirmed
- `context`: a service, account, or domain label
- `pass_len`: the desired password length, from `4` to `128`
- `character sets`: uppercase, lowercase, digits, and/or special characters
- `Argon2 profile`: the named derivation-cost profile

The library exposes the same model through:

- `enhance`
- `PasswordSettings`
- `CharacterSets`
- `CharacterSet`
- `Argon2Profile`
- `Argon2Settings`

## Pipeline

The current derivation pipeline is:

1. hash `context` with BLAKE3 to produce a 16-byte salt
2. enhance `seed` with Argon2id using that salt
3. derive a fixed 64-byte key
4. split that key into two 32-byte BLAKE3 stream keys
5. build character buckets from the selected character sets
6. shuffle the buckets with a deterministic Fisher-Yates shuffle
7. pick one character from each bucket with a deterministic byte stream
8. copy the resulting password to the clipboard

The output depends on all of these values:

- seed
- context
- password length
- selected character sets
- Argon2 memory cost
- Argon2 time cost
- Argon2 parallelism cost

Changing any of them can change the generated password.

## Determinism

Ciranda does not store generated passwords. Determinism lets a user regenerate a
password from the same stable inputs instead of saving the password somewhere
else.

That makes input discipline important. The seed and context must be typed
consistently, and profile changes should be treated as derivation-policy
changes because they also change the output.

## Cost Profiles

Argon2 exposes low-level parameters, but normal CLI usage should not require
users to tune them one by one. Ciranda therefore provides named profiles:

- `Development`: fast, low-cost settings for tests and local iteration
- `Standard`: the normal interactive profile
- `Hardened`: a high-memory profile for capable machines

The profile controls how expensive seed guessing is. It is not the recommended
rotation mechanism. Rotate by changing the seed for global rotation, or by
changing or versioning the context for service-specific rotation.

## Password Construction

The final stage constructs a password instead of encoding random bytes directly.
That gives Ciranda explicit output guarantees:

- the password length is exact
- only selected character groups are used
- every selected group appears at least once
- equivalent settings produce equivalent output

This is why the output stage uses buckets, deterministic shuffling, and
unbiased index selection instead of a direct byte-to-text encoding.
