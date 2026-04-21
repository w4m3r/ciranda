# Password Construction

Password construction turns the 64-byte Argon2id key into the final password.

This stage is deterministic. It does not request operating-system randomness.
All shuffle and character-pick decisions come from BLAKE3 streams derived from
the Argon2id output.

The construction is inspired by
[Bitwarden](https://github.com/bitwarden/clients)'s password-generation
strategy, with one intentional difference: Ciranda must derive the shuffle order
and character selection deterministically from the Argon2 output rather than
from nondeterministic randomness.

## Character Sets

Ciranda supports four character groups:

- uppercase: `A-Z`
- lowercase: `a-z`
- digits: `0-9`
- special: `!@#$%^&*`

At least one group must be selected. Unselected groups are excluded entirely
from the generated password. Every selected group contributes at least one
character to the final password.

## Canonical Order

Selected groups are normalized into this canonical order before bucket
construction:

1. uppercase
2. lowercase
3. digits
4. special

User selection order does not affect the output. Equivalent selected settings
therefore start from the same buckets before the shuffle phase.

## Buckets

Ciranda starts with one mandatory bucket for each selected character group.

If the requested password length is larger than the number of selected groups,
the remaining buckets contain the combined alphabet of all selected groups.

For example, with all groups selected and `pass_len = 6`, the initial buckets
are:

```text
[U, L, D, S, A, A]
```

Where:

- `U` is uppercase
- `L` is lowercase
- `D` is digits
- `S` is special characters
- `A` is the combined selected alphabet

If only uppercase and digits are selected, the initial buckets for
`pass_len = 6` are:

```text
[U, D, A, A, A, A]
```

In that case, `A` contains only uppercase letters and digits.

The requested password length must be between `4` and `128`. The lower bound is
a consequence of the number of all available groups and also a decision to not
increase complexity by dynamically limiting based on the number of selected
groups. It is assumed that users will not need to generate passwords shorter
than `4` characters.

## Two Byte Streams

The 64-byte Argon2id output is split into two 32-byte BLAKE3 keys:

```text
shuffle_key = key[0..32]
pick_key    = key[32..64]
```

Ciranda then creates two keyed BLAKE3 extendable-output streams:

- `ciranda:v0:shuffle`
- `ciranda:v0:pick`

The shuffle stream is used only for bucket shuffling. The pick stream is used
only for character selection.

## Fisher-Yates Shuffle

After bucket construction, Ciranda shuffles the bucket list with
[Fisher-Yates](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle).

The loop runs from the end of the list toward the beginning. At step `i`, the
algorithm chooses one bucket from the remaining prefix `[0..=i]` and swaps it
into position `i`.

After that, position `i` is final. Later iterations work only on earlier
positions.

This keeps the required character groups present while removing their fixed
positions.

## Character Picks

After shuffling, Ciranda picks one character from each bucket.

A mandatory uppercase bucket produces one uppercase character. A combined
alphabet bucket produces one character from the selected alphabet.

Because there is one bucket per output position, the password length is exact.

## Rejection Sampling

Whenever Ciranda needs an index in a bounded range, it uses rejection sampling
instead of plain modulo reduction.

Plain modulo can bias the result when the source integer range is not evenly
divisible by the target range. Rejection sampling avoids that by discarding
values from the uneven tail before applying modulo.

The process is:

1. read a byte from the deterministic stream
2. compute the largest evenly divisible prefix for the target range
3. reject values outside that prefix
4. apply modulo to accepted values

This keeps index selection unbiased while preserving determinism.

## Index Sampling

The deterministic streams produce bytes, and Ciranda samples indexes from one
byte at a time. Rejection-sampling arithmetic is done with `u16` so the sampler
can represent the full byte source size of `256`.
