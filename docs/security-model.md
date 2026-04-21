# Security Model

Ciranda derives passwords from stable inputs. It does not store generated
passwords, and it does not use operating-system randomness during password
construction.

The security model depends on choosing a strong seed, using meaningful contexts,
and selecting an Argon2 profile appropriate for the machine and use case.

## What Ciranda Protects Against

Ciranda is designed to make offline guessing of the seed expensive.

If an attacker knows or guesses a context and has a target password to compare
against, they still need to test candidate seeds through Argon2id. The selected
profile controls how costly each guess is.

Different contexts produce different salts, so work for one context does not
directly reuse the same derived key for another context.

## What Ciranda Does Not Protect Against

Ciranda cannot protect a weak seed by itself. A short, common, or reused seed is
still guessable.

Ciranda also does not protect against:

- malware or keyloggers on the machine where the seed is typed
- clipboard capture after the password is copied
- inconsistent context spelling
- forgetting the seed or context
- websites that reject the selected password alphabet

The generated password is deterministic. Anyone who learns the exact inputs and
settings can regenerate it.

## Seed Guidance

The seed is the main secret. It should be long, memorable, and unique to
Ciranda.

Because the same seed can derive many passwords, losing the seed has broad
impact. Changing the seed is the global rotation mechanism.

## Context Guidance

The context separates derived passwords. It should identify the service,
account, or purpose clearly enough that the same value can be entered again.

For service-specific rotation, change or version the context. For example:

```text
github
github:2026
github:work
```

The context is not secret. Its main job is domain separation.

## Profile Guidance

Use `Standard` for normal interactive use.

Use `Development` only for tests, examples, and fast local iteration. It is not
a security target.

Use `Hardened` only when the machine can intentionally spend much more memory.
It provides a higher-cost derivation, but it can be inappropriate on
constrained systems.

Changing the profile changes the generated password. Treat profile changes as
derivation-policy changes, not as the normal rotation mechanism.

## Deterministic Output

Determinism is central to Ciranda. It lets the same password be regenerated
without storing it.

The cost is that input stability matters. The same service should use the same
context spelling, the same selected character sets, the same password length,
and the same profile unless the user intentionally wants a different password.

## Character-Set Compatibility

Character-set selection is a compatibility feature. It lets users exclude
groups that a service does not accept.

Every selected group appears at least once, and every unselected group is
excluded entirely. If a service has unusual password rules, the selected groups
and length should be chosen to match those rules before generating the password.
