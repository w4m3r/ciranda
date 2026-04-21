# Key Derivation

Ciranda uses Argon2id and BLAKE3 for different jobs.

Argon2id enhances the human-entered seed. BLAKE3 derives fixed-width context
hashes and deterministic byte streams. BLAKE3 is not used as a password KDF.

## Seed And Context

Ciranda keeps `seed` and `context` in separate roles:

- `seed` is passed to Argon2id as the secret input
- `context` is hashed into the Argon2id salt

The structure is:

```text
Argon2id(password = seed, salt = BLAKE3-128(domain || context))
```

The final key depends on both values.

## Salt Derivation

The salt is:

```text
BLAKE3-128("ciranda:v0:salt" || context)
```

Ciranda uses a 16-byte salt. That gives a 128-bit salt value, which is a
standard and adequate size for Argon2id.

The salt is not meant to be secret. Its role is to separate derived keys across
contexts and prevent the same seed from producing the same key everywhere.

The `ciranda:v0:salt` domain string keeps salt derivation distinct from other
BLAKE3 uses in the design.

## Argon2id

Ciranda uses Argon2id as the fixed Argon2 variant.

Argon2id is the appropriate default here because Ciranda works with a
human-entered secret. The KDF should make offline guessing expensive, and it
should not assume that side-channel timing attacks are irrelevant.

Ciranda does not expose Argon2d or Argon2i selection in the normal public model.
The user-facing security choice is the profile, not the variant.

## Profiles

Profiles resolve to `Argon2Settings`, which contain:

- `m_cost`: memory cost in KiB
- `t_cost`: iteration count
- `p_cost`: parallelism degree

The current profiles are:

| Profile | Memory | Time | Parallelism | Use |
| --- | ---: | ---: | ---: | --- |
| `Development` | `8 KiB` | `1` | `1` | tests and fast local iteration |
| `Standard` | `64 MiB` | `3` | `4` | normal interactive use |
| `Hardened` | `2 GiB` | `1` | `4` | high-memory use on capable machines |

`Standard` should be the default for normal use. `Development` is not a
security target. `Hardened` should be selected only when the machine can
intentionally spend the extra memory.

## Derived Key Size

Ciranda asks Argon2id for a fixed 64-byte output.

That output is split into two 32-byte BLAKE3 keys:

```text
shuffle_key = key[0..32]
pick_key    = key[32..64]
```

This fits the downstream design because BLAKE3 keyed hashing uses 32-byte keys,
and Ciranda uses two independent deterministic streams.

The 64-byte size is a clean engineering fit for the stream design. It should not
be interpreted as a claim that the final password has 64 bytes of security. The
effective security depends mostly on the strength of the seed, the Argon2id
cost profile, and the consistency of the context used for each service.

## References

- RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
  Applications: <https://www.rfc-editor.org/rfc/rfc9106.html>
