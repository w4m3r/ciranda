# BLAKE3-Argon2 Dynamic

Ciranda uses BLAKE3 and Argon2id in three places:

```text
context -> BLAKE3 salt derivation
seed + salt -> Argon2id -> 64-byte key
64-byte key -> BLAKE3 streams -> password
```

BLAKE3 first derives the Argon2 salt from the context. Argon2id then does the
memory-hard work over the seed and salt. After that, BLAKE3 derives
deterministic byte streams for password construction.

## BLAKE3 Output Sizes

BLAKE3's normal hash output is 32 bytes. In the Rust crate, `finalize()`
returns a `Hash`, and `Hash::as_bytes()` exposes a `[u8; 32]`.

BLAKE3 can also produce more or fewer bytes through XOF mode:

```rust
let mut output = [0u8; 64];
hasher.finalize_xof().fill(&mut output);
```

That means the 32-byte value is the default digest size, not the only possible
output size.

## Salt Derivation

Ciranda derives the Argon2 salt from the context:

```text
salt = BLAKE3("ciranda:v0:salt" || context)[0..16]
```

The salt is 16 bytes. BLAKE3's standard 32-byte digest is already longer than
that, so the implementation hashes the domain and context, then copies the
first 16 bytes.

The same 16 bytes could also be produced with XOF mode:

```rust
let mut salt = [0u8; 16];
hasher.finalize_xof().fill(&mut salt);
```

Using the standard digest and slicing it is clear for this case because the
salt is a truncated context hash, not an arbitrary-length stream.

The `ciranda:v0:salt` string is a domain separator. It makes the salt a
Ciranda-specific hash of the context instead of a bare `BLAKE3(context)`.

Repeated `update` calls should be understood as feeding one ordered byte stream
into the hasher:

```text
update(domain)
update(context)
finalize()

hashes the same logical input as:

domain || context
```

BLAKE3 may compress chunks before `finalize`, but the digest is defined over
all bytes that were fed, in order.

## Argon2 Output Size

Argon2 supports variable-length output. In the Rust `argon2` crate, the default
output length is 32 bytes when the password-hash API needs a default.

Ciranda does not use that default. It explicitly requests a 64-byte key:

```text
Argon2id(seed, salt, settings) -> 64 bytes
```

Argon2's final output function is based on BLAKE2b. BLAKE2b naturally supports
digest sizes up to 64 bytes. Because of that, Argon2 outputs of 32 bytes and 64
bytes are in the same direct-output category: both fit within one BLAKE2b-sized
final digest.

When Argon2 is asked for more than 64 bytes, it uses its specified
BLAKE2b-based longer-output expansion. That produces more bytes, but it does
not add more memory-hard work. Increasing `m_cost` or `t_cost` changes the
offline-guessing cost; increasing output length mostly changes finalization.

## Current Stream Split

Ciranda currently splits the 64-byte Argon2 output into two 32-byte keys:

```text
shuffle_key = key[0..32]
pick_key    = key[32..64]
```

Each half is used as a BLAKE3 keyed-mode key:

```text
BLAKE3 keyed with shuffle_key, input "ciranda:v0:shuffle" -> shuffle stream
BLAKE3 keyed with pick_key, input "ciranda:v0:pick"       -> pick stream
```

This is a convenient fit:

- Argon2 can produce 64 bytes without using its longer-output expansion path.
- BLAKE3 keyed mode expects a 32-byte key.
- Ciranda currently needs two deterministic streams.

So the 64-byte Argon2 output divides neatly into two BLAKE3 stream keys. This
is a useful alignment, not a requirement imposed by the primitives.

## Why Keyed Mode

The Argon2 output is secret internal key material. BLAKE3 keyed mode expresses
that role directly:

```text
BLAKE3(key = secret stream key, input = public purpose label)
```

The alternative would be to use unkeyed BLAKE3 and pass the key bytes as normal
input:

```text
BLAKE3(input = secret bytes || purpose label)
```

That would likely work here, but it is less explicit. Keyed mode avoids
inventing an ad hoc encoding for secret material and public labels.

## Domain Labels

The current stream labels are:

```text
ciranda:v0:shuffle
ciranda:v0:pick
```

Because the streams already use different 32-byte keys, these labels are not
the primary separation mechanism today. The streams are separated mostly by the
key split.

The labels still make the transcript self-describing and bind each stream to a
purpose. They would become more important if Ciranda later moved to a root-key
design.

## Rejection Sampling And Stream Length

The shuffle stream does not consume a fixed 32 bytes. It consumes as many bytes
as Fisher-Yates and rejection sampling require.

For a password of length `n`, Fisher-Yates needs `n - 1` accepted indexes.
Ciranda reads one byte per candidate index.

Rejection sampling can consume more bytes when a candidate value is rejected.
Rejection-sampling arithmetic is done with `u16` so the sampler can represent
the full byte source size of `256`. With the current maximum password length of
`128`, the largest shuffle bound fits comfortably in a byte-sized source.

The pick stream also consumes one accepted index per password character. BLAKE3
XOF mode is useful because both streams can provide as many bytes as needed
without precomputing an exact length.

## Possible Root-Key Alternative Design

An alternative design would treat the 64-byte Argon2 output as one root key and
derive named stream keys from it:

```text
Argon2id -> 64-byte root key

BLAKE3(root key, "shuffle-key") -> 32-byte shuffle key
BLAKE3(root key, "pick-key")    -> 32-byte pick key

BLAKE3 keyed with shuffle key -> shuffle stream
BLAKE3 keyed with pick key    -> pick stream
```

In that design, the domain labels would be the core separation mechanism. Each
stream key would be derived from the full Argon2 output and a purpose label.

That would make future stream additions easier and avoid tying the design to a
two-way split. The current split remains defensible because each half is already
a full 32-byte BLAKE3 key and Argon2 output is expected to be pseudorandom.

The practical guidance is:

- keep the current split if the two-stream design remains stable
- prefer a root-key, domain-separated derivation if new streams are added
- do not use uneven splits merely because one stream consumes more bytes

Different stream consumption does not mean a stream needs more seed material.
Once BLAKE3 is keyed with strong material, XOF mode can provide a long
deterministic stream.
