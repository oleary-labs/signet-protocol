# At-Rest Value Encryption: Implementation Spec

**Version:** 1.0 (draft)
**Status:** For implementation
**Scope:** Encrypt the *values* stored in our sled-backed KV layer in a way that is structurally compatible with a future migration to a TEE-backed key-custody source (Turnkey-style QuorumOS or similar). Keys remain plaintext.

---

## 1. Overview

We currently store records in sled with no encryption. This spec defines an envelope-encryption scheme for stored values that:

- Provides confidentiality at rest against an adversary who can read or modify the on-disk database files.
- Provides per-record integrity (tampering is detected on read).
- Binds each ciphertext to its addressing context (anti-swap).
- Cleanly separates **key custody** (who holds the root key, where unwrap operations run) from **storage** (where ciphertext is persisted), so that migrating either to a TEE-backed implementation is a trait-impl swap, not a data format change.
- Supports rolling KEK rotation without a full re-encryption sweep.

The design mirrors the envelope encryption pattern used by AWS KMS, GCP KMS, HashiCorp Vault, and Turnkey's QuorumOS-backed wallet storage: a long-lived **KEK** (key-encryption key) wraps short-lived **DEK**s (data-encryption keys), one per record.

---

## 2. Goals

| # | Goal |
|---|------|
| G1 | Confidentiality of stored values against an attacker with read access to sled files. |
| G2 | Tamper-evidence per record (AEAD authentication tag verification on read). |
| G3 | Anti-swap: a ciphertext copied from one record to another must fail to decrypt. |
| G4 | Forward-compatible migration to TEE custody with no data-format change. |
| G5 | Forward-compatible migration of storage backend (sled → S3 / DynamoDB / Postgres / etc.) with no crypto-format change. |
| G6 | KEK rotation without immediate bulk re-encryption. |
| G7 | Deterministic ciphertext framing with explicit version byte so the format can evolve. |

## 3. Non-Goals

| # | Non-goal | Why deferred |
|---|----------|--------------|
| N1 | Confidentiality of database **keys** (sled keys). | Our identifiers are low-entropy OAuth-derived strings (`<iss><sub>`-shaped) and not PII. Deterministic encryption is dictionary-attackable on low-entropy spaces, and the operational cost (no plaintext iteration, custody round-trips for lookups) does not justify the marginal security gain. |
| N2 | Anti-rollback / freshness (preventing replay of an old encrypted snapshot). | Requires a notarizer-style signed-heartbeat mechanism. Out of scope for v1; sketched in §11. |
| N3 | Detection of record **deletion** or reordering across the whole DB. | Requires a per-DB signed Merkle log of all records. Out of scope for v1; sketched in §11. |
| N4 | Searchable encryption / encrypted indexes. | Not needed; iteration within a tree is sufficient for our access patterns. |
| N5 | Authentication of *writers* (who is allowed to call `insert`). | Enforced at the application layer above this module. |

## 4. Threat Model

**In scope:**

- Adversary reads on-disk sled files (backup theft, disk forensics, snapshot exfiltration).
- Adversary modifies on-disk sled files between writes (bit-flips, truncation, ciphertext substitution).

**Out of scope:**

- Adversary reads process memory.
- Adversary tampers with the running binary.
- Adversary has access to the custody source (e.g., the sealed KEK file or, post-migration, the enclave).

The threat model expands cleanly under TEE migration: post-migration, "adversary reads process memory of the host service" becomes in-scope-but-defeated, because the KEK never enters host memory.

## 5. Cryptographic Primitives

| Role | Primitive | Notes |
|------|-----------|-------|
| KDF | HKDF-SHA-256 (RFC 5869) | Used to derive per-purpose sub-keys from the root KEK. |
| Value AEAD | XChaCha20-Poly1305 (RFC 8439 + IETF draft for XChaCha) | 256-bit key, 192-bit nonce, 128-bit tag. Random nonces are safe at any practical record count. |
| DEK wrapping AEAD | XChaCha20-Poly1305 | Same primitive, separate key. |
| DEK | 32 random bytes from a CSPRNG (e.g., `OsRng`). | One per record, never reused. |
| KEK | 32 random bytes, generated out-of-band, loaded from sealed config file. | Rotated by adding a new version. |
| RNG | OS CSPRNG (`getrandom(2)` on Linux). | All nonces and DEKs MUST come from this source. |

**Rust crates:**

- `chacha20poly1305` (RustCrypto) for the AEAD.
- `hkdf` (RustCrypto) for HKDF.
- `zeroize` for `Zeroizing<…>` wrappers around all key material.
- `getrandom` for entropy.

XChaCha20-Poly1305 is preferred over AES-256-GCM for v1 because the 192-bit nonce eliminates any nonce-collision concern under random selection. If we later need hardware-accelerated AES for perf, the AEAD can be swapped under a new version byte without changing the record framing.

## 6. Record Format (v1, version byte = `0x01`)

All multi-byte integers are big-endian. All fields are fixed-size within a version; future versions may change sizes by bumping the version byte.

```
record_bytes:
    +---------------------+--------+------------------------+
    | version             | 1 byte | 0x01                   |
    +---------------------+--------+------------------------+
    | kek_version         | 1 byte | identifies which KEK   |
    |                     |        | generation wrapped DEK |
    +---------------------+--------+------------------------+
    | wrap_nonce          | 24 B   | random per record      |
    +---------------------+--------+------------------------+
    | wrapped_dek         | 48 B   | XChaCha-P1305(KEK[kv]) |
    |                     |        | of 32-byte DEK + tag   |
    +---------------------+--------+------------------------+
    | value_nonce         | 24 B   | random per record      |
    +---------------------+--------+------------------------+
    | value_ciphertext    | var    | XChaCha-P1305(DEK)     |
    |   (plaintext_len    |        | of value + tag         |
    |    + 16 byte tag)   |        |                        |
    +---------------------+--------+------------------------+
```

Total fixed overhead per record: **98 bytes** (1 + 1 + 24 + 48 + 24).

`kek_version` is distinct from `version`. The latter governs the record framing (sizes, AEADs, AAD layout). The former identifies which KEK generation should unwrap the DEK; it advances with each KEK rotation and is independent of framing changes.

## 7. AAD Construction

Both AEAD operations take associated data (AAD) that binds the ciphertext to its addressing context. AAD is the byte-concatenation (no separators inside; lengths are determined by the field order and the version byte):

```
common_prefix = version || kek_version || tree_name_len_u16_be || tree_name || record_key_len_u32_be || record_key

dek_aad   = common_prefix || b"dek/v1"
value_aad = common_prefix || b"val/v1" || wrap_nonce || wrapped_dek
```

Notes:

- `tree_name` is the logical group/schema name (the sled `Tree` name).
- `record_key` is the **plaintext** sled key for this record. Per §3 N1, sled keys are not encrypted in v1.
- `value_aad` includes the wrap nonce and wrapped DEK ciphertext. This pins the value encryption to the exact wrapping that produced its DEK; an attacker cannot substitute a different wrapped DEK without breaking value-AEAD verification.
- The `"dek/v1"` and `"val/v1"` literals provide domain separation between the two AEAD uses so a wrapped DEK can never be parsed as a value ciphertext or vice versa.

## 8. The `KeyCustody` Trait

This is the migration seam for the KEK. Today it holds bytes in memory; tomorrow it talks to an enclave.

```rust
use std::sync::Arc;
use zeroize::Zeroizing;

pub type Dek = Zeroizing<[u8; 32]>;

#[derive(Clone)]
pub struct WrappedDek {
    pub kek_version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: [u8; 48], // 32 (DEK) + 16 (tag)
}

#[derive(thiserror::Error, Debug)]
pub enum CustodyError {
    #[error("unknown kek version: {0}")]
    UnknownKekVersion(u8),
    #[error("aead failure")]
    Aead,
    #[error("custody backend: {0}")]
    Backend(String),
}

pub trait KeyCustody: Send + Sync {
    /// The KEK version this custody will use for new wraps. Read on every
    /// insert so rotation takes effect without restart.
    fn current_kek_version(&self) -> u8;

    /// Wrap a freshly generated DEK with the current KEK.
    fn wrap_dek(&self, dek: &Dek, aad: &[u8]) -> Result<WrappedDek, CustodyError>;

    /// Unwrap a DEK previously wrapped by any KEK version this custody knows.
    /// Returns `UnknownKekVersion` if the version is not in the known set.
    fn unwrap_dek(&self, wrapped: &WrappedDek, aad: &[u8]) -> Result<Dek, CustodyError>;
}
```

### 8.1 `LocalKeyCustody` (v1, in-process)

```rust
pub struct LocalKeyCustody {
    keks: std::collections::BTreeMap<u8, Zeroizing<[u8; 32]>>,
    current: u8,
}

impl LocalKeyCustody {
    /// Load KEKs from the configured sealed file. The file format is a JSON
    /// or TOML document of {kek_version: u8, key_b64: String} entries, plus
    /// a `current_kek_version` field. File MUST be mode 0600 and owned by
    /// the service user.
    pub fn from_config(path: &std::path::Path) -> anyhow::Result<Self> { … }
}
```

Implementation requirements:

- KEKs MUST live in `Zeroizing` wrappers and be zeroed on drop.
- `wrap_dek` derives the wrapping sub-key via HKDF: `hkdf_expand(kek[current], info = b"at-rest/dek-kek/v1", okm_len = 32)`. The resulting 32-byte key feeds XChaCha20-Poly1305.
- `unwrap_dek` does the same derivation against the KEK identified by `wrapped.kek_version`.
- The HKDF info string includes a version so that a future framing change can use a different sub-key without changing KEKs.

### 8.2 `EnclaveKeyCustody` (post-migration, sketch)

```rust
pub struct EnclaveKeyCustody {
    client: VsockClient,           // vsock to enclave-side custody service
    cached_current_version: AtomicU8, // refreshed on a heartbeat
}
```

The enclave-side service performs the same HKDF derivation and AEAD operations using KEK material that never leaves the enclave. The `WrappedDek` byte layout is unchanged. Existing records remain decryptable as long as the same KEK material is bootstrapped into the enclave (one-time sealed import on first enclave provisioning) or as long as the records have already been re-wrapped under a new in-enclave KEK via the rotation mechanism (§10).

## 9. The `Storage` Trait

The other migration seam. Today is sled; tomorrow could be anything the enclave's parent can reach.

```rust
pub trait Storage: Send + Sync {
    fn get(&self, tree: &str, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn insert(&self, tree: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    fn remove(&self, tree: &str, key: &[u8]) -> anyhow::Result<()>;

    /// Returns an iterator over (key, value) pairs in the given tree.
    /// Order is implementation-defined and not guaranteed.
    fn iter<'a>(
        &'a self,
        tree: &str,
    ) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<(Vec<u8>, Vec<u8>)>> + 'a>>;
}
```

`SledStorage` is the v1 implementation. Future implementations (`S3Storage`, `DynamoStorage`, etc.) require no crypto changes.

## 10. The `EncryptedStore` API

```rust
pub struct EncryptedStore<S, C> {
    storage: S,
    custody: C,
}

impl<S: Storage, C: KeyCustody> EncryptedStore<S, C> {
    pub fn new(storage: S, custody: C) -> Self { Self { storage, custody } }

    pub fn get(&self, tree: &str, key: &[u8]) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;
    pub fn insert(&self, tree: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    pub fn remove(&self, tree: &str, key: &[u8]) -> anyhow::Result<()>;

    /// Decrypting iterator. Yields `(key, plaintext_value)`. Records that fail
    /// AEAD verification yield an error; the iterator does NOT silently skip
    /// them.
    pub fn iter<'a>(
        &'a self,
        tree: &str,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<(Vec<u8>, Zeroizing<Vec<u8>>)>> + 'a>;
}
```

### 10.1 `insert` algorithm

```
1.  dek         = csprng(32)
2.  wrap_nonce  = csprng(24)
3.  value_nonce = csprng(24)
4.  kek_version = custody.current_kek_version()
5.  dek_aad     = build_common_prefix(0x01, kek_version, tree, key) || b"dek/v1"
6.  wrapped     = custody.wrap_dek(dek, dek_aad)   // returns WrappedDek
7.  value_aad   = build_common_prefix(0x01, kek_version, tree, key)
                  || b"val/v1" || wrap_nonce || wrapped.ciphertext
8.  value_ct    = XChaCha20-Poly1305(dek).seal(value_nonce, value, value_aad)
9.  record      = serialize(0x01, kek_version, wrap_nonce, wrapped.ciphertext,
                            value_nonce, value_ct)
10. storage.insert(tree, key, record)
```

### 10.2 `get` algorithm

```
1.  bytes = storage.get(tree, key)?  // None ⇒ return None
2.  (version, kek_version, wrap_nonce, wrapped_ct, value_nonce, value_ct)
        = parse(bytes)?
3.  if version != 0x01 ⇒ Err(UnsupportedRecordVersion)
4.  dek_aad   = build_common_prefix(version, kek_version, tree, key) || b"dek/v1"
5.  dek       = custody.unwrap_dek(WrappedDek { kek_version, nonce: wrap_nonce,
                                                 ciphertext: wrapped_ct }, dek_aad)
6.  value_aad = build_common_prefix(version, kek_version, tree, key)
                || b"val/v1" || wrap_nonce || wrapped_ct
7.  plaintext = XChaCha20-Poly1305(dek).open(value_nonce, value_ct, value_aad)
8.  return Some(Zeroizing::new(plaintext))
```

### 10.3 `iter` algorithm

Stream `storage.iter(tree)`, applying `get`-style decryption for each entry. Yields `(plaintext_key, Zeroizing<plaintext_value>)`. AEAD failures propagate; do not skip silently.

## 11. KEK Rotation

Rotation does not require immediate re-encryption.

1. Operator generates a new 32-byte KEK and appends it to the sealed config file with the next version number. Updates `current_kek_version` to the new value.
2. Service is signalled (SIGHUP, file watcher, or restart) to reload the config. `LocalKeyCustody` now knows both the old and new KEK; `current_kek_version()` returns the new one.
3. All subsequent `insert`s write records with the new `kek_version`.
4. Existing records continue to be decryptable because `unwrap_dek` honors the `kek_version` field in each record.
5. (Optional) A background sweep re-encrypts old records under the new KEK by reading and re-writing each. This is purely a hygiene operation and can run at any rate.
6. (Optional) After the sweep completes and operator verifies no records reference the old version, the old KEK can be removed from the config.

Old KEK material MUST be retained until step 5 is complete.

## 12. Migration to TEE-backed Custody

The protocol-level changes when we migrate from `LocalKeyCustody` to an enclave-resident custody implementation:

1. **Record format:** No change. Existing records remain decryptable.
2. **Wire format on disk:** No change.
3. **KeyCustody impl:** Swap `LocalKeyCustody` for `EnclaveKeyCustody`. The trait is unchanged.
4. **KEK bootstrap:** The current local KEK material is imported into the enclave via a sealed one-time channel during enclave provisioning. After import, the enclave can `unwrap_dek` against all existing records. Subsequent rotations (§10) happen with KEK material that is generated inside the enclave and never seen by the host.
5. **Storage backend:** May be swapped at the same time or independently. If the enclave's host can reach sled over a local FS mount, `SledStorage` continues to work; otherwise swap for an `S3Storage` / `DynamoStorage` / etc., all of which require no crypto-format change.

The migration is therefore at most: implement `EnclaveKeyCustody`, define the sealed-import protocol for KEK bootstrap, deploy alongside the existing service, and feature-flag the swap.

## 13. Future Extensions (out of scope for v1, sketched here for placement)

These extensions add capabilities the v1 spec deliberately omits. They slot in cleanly without changing v1 records or the existing traits.

### 13.1 Per-DB tamper-evident log (anti-deletion, anti-reordering)

Add a separate signing trait analogous to `KeyCustody`:

```rust
pub trait LogSigner: Send + Sync {
    fn sign(&self, prev_root: &[u8; 32], record_hash: &[u8; 32]) -> [u8; 64];
    fn verify(&self, prev_root: &[u8; 32], record_hash: &[u8; 32], sig: &[u8; 64]) -> bool;
}
```

Maintain a single "log root" sled key (e.g., `__meta/log_root`) that holds the most recent signed root. Every `insert` appends a log entry containing `(tree, key, record_hash)`, computes the new root via Merkle accumulation, and signs it. On `get`, verify a Merkle inclusion proof against the current root before returning. This addresses non-goal **N3**.

### 13.2 Freshness / anti-rollback

Add a heartbeat-signing service ("notarizer") that periodically signs `(log_root, current_timestamp)`. On `get`, require that the most recent heartbeat be no older than a configured staleness window. This addresses non-goal **N2**.

### 13.3 Field-level subkey custody

If specific fields ever need keys that are not derivable from the main KEK (e.g., a per-tenant key that customers can revoke independently), extend `KeyCustody` with a `derive_subkey(label) -> SubkeyHandle` method whose result can be used in place of the global custody for selected records. The record format already supports this via the `kek_version` field — extend semantics so that values above `0xC0` (say) denote subkey handles rather than KEK generations.

## 14. Required Tests

The implementation MUST pass at least the following test cases.

### 14.1 Round-trip

- Insert `(tree, key, value)` and `get` returns the same value.
- Insert with empty value succeeds and `get` returns empty value.
- Insert with empty key succeeds (sled supports this) and `get` returns the value.

### 14.2 Tamper detection

For each of the following, mutate the on-disk record bytes and assert that `get` returns an error (not `None`, not a silent corruption):

- Flip a bit in `value_ciphertext`.
- Flip a bit in the value AEAD tag (last 16 bytes of `value_ciphertext`).
- Flip a bit in `wrapped_dek`.
- Flip a bit in `wrap_nonce`.
- Flip a bit in `value_nonce`.
- Truncate the record.
- Replace `version` with `0x02`.
- Replace `kek_version` with an unknown version.

### 14.3 Anti-swap

- Insert `(tree, "a", value_a)` and `(tree, "b", value_b)`.
- Read both records' raw bytes from storage. Swap them on disk.
- Assert that both `get(tree, "a")` and `get(tree, "b")` now fail with AEAD error.

### 14.4 Cross-tree anti-swap

- Insert `(tree_x, "k", v)` and copy the raw record bytes to `(tree_y, "k")`.
- Assert that `get(tree_y, "k")` fails with AEAD error.

### 14.5 KEK rotation

- Insert record under KEK version `0x01`.
- Rotate to KEK version `0x02`.
- `get` of the old record still succeeds.
- New inserts produce records with `kek_version = 0x02`.
- After re-inserting the old record, its on-disk `kek_version` byte is now `0x02`.

### 14.6 Unknown KEK version

- Manually construct a record with `kek_version = 0xFF`.
- `get` returns `CustodyError::UnknownKekVersion(0xFF)`.

### 14.7 Determinism of AAD

- Encrypt the same value to the same `(tree, key)` twice. Ciphertexts MUST differ (different DEKs, different nonces). Both MUST decrypt to the same plaintext.

### 14.8 Iteration

- Insert N records across multiple trees. Iterate one tree and assert all and only that tree's records are yielded with correct plaintexts.

## 15. Operational Requirements

- **KEK file permissions:** mode `0600`, owned by service user. Service refuses to start if perms are looser.
- **Memory hygiene:** all `KEK`, `DEK`, and plaintext value buffers MUST use `Zeroizing` so they are zeroed on drop. Avoid `String` for plaintext values — use `Zeroizing<Vec<u8>>`.
- **Error reporting:** AEAD failures MUST NOT include the failing ciphertext or key material in error messages or logs. Log at most `tree` and `key` (which are plaintext anyway) and the error kind.
- **Concurrency:** the `EncryptedStore` is `Send + Sync` if `S` and `C` are. `LocalKeyCustody` uses interior mutability only for rotation reload; reads are lock-free.
- **No serde derives on key material:** never serialize a `Dek` or KEK through `serde`. The only key material that crosses serialization boundaries is the *wrapped* DEK inside a record.

## 16. Open Questions

| # | Question | Default if not resolved |
|---|----------|-------------------------|
| Q1 | Do we need to encrypt values smaller than some threshold (e.g., a few bytes), where the 98-byte fixed overhead is significant? | Encrypt all values uniformly. Storage cost of small records is not a bottleneck. |
| Q2 | Do we want a separate config field per `tree` to opt out of encryption (e.g., for cache trees)? | Default: all trees encrypted. Add per-tree opt-out only if a concrete need emerges. |
| Q3 | Should the KEK config file format support a comment field per KEK version (e.g., creation date, operator)? | Yes; treat as a free-form `metadata: HashMap<String, String>` per KEK entry. Not security-relevant; useful for ops. |
| Q4 | Where in the codebase does the `EncryptedStore` boundary sit? | TBD with implementer — should wrap the lowest layer that currently calls sled directly. |

---

## Appendix A. Reference encoding of `common_prefix`

```
let mut prefix = Vec::with_capacity(2 + 2 + tree.len() + 4 + key.len());
prefix.push(version);
prefix.push(kek_version);
prefix.extend_from_slice(&(tree.len() as u16).to_be_bytes());
prefix.extend_from_slice(tree.as_bytes());
prefix.extend_from_slice(&(key.len() as u32).to_be_bytes());
prefix.extend_from_slice(key);
```

`tree` is restricted to UTF-8; length-prefixed by `u16` (max 65535 bytes — plenty).
`key` is arbitrary bytes; length-prefixed by `u32`.

## Appendix B. Reference record serialization

```
let mut record = Vec::with_capacity(98 + value_ct.len());
record.push(0x01);                          // version
record.push(wrapped.kek_version);
record.extend_from_slice(&wrapped.nonce);   // 24 B
record.extend_from_slice(&wrapped.ciphertext); // 48 B
record.extend_from_slice(&value_nonce);     // 24 B
record.extend_from_slice(&value_ct);        // variable
```

Parsing is the inverse, with strict length checks: a record shorter than 98 bytes is invalid framing (distinct error from AEAD failure).
