# Bounded-size store path signatures for Nix

*Design note, 2026-10-12. Companion to [README.md](README.md), which holds the experiments.*

## 1. The problem

Nix authenticates a store path with a detached signature over its *fingerprint*

```
1;<store path>;sha256:<nar hash, nix32>;<nar size>;<ref 1>,<ref 2>,...
```

(`ValidPathInfo::fingerprint`, `src/libstore/path-info.cc`). The signature is pure Ed25519
(`crypto_sign_detached`, `src/libutil/signature/local-keys.cc`) and is stored as
`Sig: <key name>:<base64>` in `.narinfo` files. Pure Ed25519 has no hash-then-sign step the
caller can take over: the signer needs the *whole* message, twice.

That is harmless with a key in a file and fatal with a key in hardware. The fingerprint has no
upper bound: it grows by one full store path per reference. Over this machine's running NixOS
closure (3392 paths):

| | |
|---|---|
| median fingerprint | 291 bytes |
| 90th percentile | 771 bytes |
| over 1024 bytes | 227 paths (6.7 %), everything with more than ~15 references |
| over 2048 bytes | 97 paths (2.9 %), everything with more than ~32 references |
| largest | 48 076 bytes, 625 references (`emacs-packages-deps`); `system-path` 22 196, `plasma-workspace` 8 928, `firefox` 2 133 |

And every pure-Ed25519 signer that is not a CPU has a message cap (section 3). On the trussed
`piv-authenticator` the cap is 1024 bytes and the applet *panics* past it; on a YubiKey it is
about 3 KB; on a YubiHSM 2 it is 2019 bytes. So a hardware-backed cache key can sign leaf
packages and nothing with a real dependency list. The reference list is the problem, not the
algorithm.

## 2. Prior work

### In Nix

- **Upstream Nix** (`NixOS/nix`): Ed25519 only, one code path, no algorithm tag anywhere.
  [PR 15926](https://github.com/NixOS/nix/pull/15926) (edolstra, open since 2026-05-27) makes
  `PublicKey` and `SecretKey` polymorphic with a `KeyType` enum, as scaffolding; it adds no
  algorithm. This is the insertion point for anything below.
- **Determinate Nix**: [nix-src PR 449](https://github.com/DeterminateSystems/nix-src/pull/449)
  (merged 2026-05-20, shipped in 3.21.0) adds, behind `experimental-features = cnsa`,
  **ECDSA P-384** and **ML-DSA-44/65/87**. Keys stay `name:base64`; a 32-byte blob is Ed25519,
  anything else is DER (SubjectPublicKeyInfo / PKCS#8) handed to OpenSSL, whose key type decides
  the algorithm. ECDSA signs `SHA-384(fingerprint)` through `EVP_DigestSign` with RFC 6979
  nonces and stores the DER `ECDSA-Sig-Value`. `Sig:` lines are untouched. New CLI:
  `nix key generate-secret --key-type ecdsa-p384`, `nix key convert-{public,secret}-to-pem`.
  [PR 466](https://github.com/DeterminateSystems/nix-src/pull/466) (draft) loads keys from
  PKCS#11 URIs through OpenSSL's `OSSL_STORE`, tested with
  [nixpkcs](https://github.com/numinit/nixpkcs). Neither PR mentions message size.
- **RFC 202** ([NixOS/rfcs#202](https://github.com/NixOS/rfcs/pull/202), hybrid Ed25519 +
  ML-DSA-65 in a `Sig-PQC:` field over the same fingerprint) was closed in July 2026 as
  superseded by the extensible key representation of PR 449/15926.
- **Everyone else** reimplements `1;` + Ed25519 and nothing else: snix `nix-compat`
  (`narinfo::fingerprint`, `VerifyingKey`), go-nix, cachix `nix-narinfo`, attic (managed
  signing on upload), harmonia (via libnixstore), nix-serve-ng, niks3, cf-nix-cache.

### Elsewhere, same problem

- **minisign** (libsodium's author; Nix uses the same `crypto_sign_detached`) added a prehashed
  mode: sign `BLAKE2b-512(file)` instead of the file, tagged `ED` instead of `Ed` in the
  signature, default since 0.10. Motivation: large files and HSM/KMS message caps.
- **OpenPGP cards** never see the message: the host hashes, the card signs the digest. Ed25519 on
  a YubiKey or Nitrokey via GnuPG therefore has no size problem at all.
- **OpenSC** capped raw `C_Sign` input at 512 bytes until 0.22 (2021); the limit was lifted
  because pure EdDSA cannot sign an X.509 certificate otherwise
  ([OpenSC#2300](https://github.com/OpenSC/OpenSC/issues/2300)).
- **AWS KMS** added Ed25519 in November 2025 with a 4096-byte raw cap and a separate
  `ED25519_PH_SHA_512` mode for digests.

## 3. What the hardware accepts

Message caps for a **raw Ed25519** signature, and whether a prehash variant exists:

| signer | raw Ed25519 message | Ed25519ph | ECDSA P-384 over digest |
|---|---|---|---|
| trussed apps (Solo 2, Nitrokey 3): piv-authenticator, opcard | 1024 B (`MAX_MESSAGE_LENGTH`), 2048 with `mldsa44`; solo2 PIV panics above | no | yes (48 B) |
| YubiKey 5 PIV, firmware 5.7.4 | about 3000 B works, 4096 refused with `6700`; not documented by Yubico (ykpiv buffer 3072) | no | yes, since firmware 4 |
| YubiHSM 2 | 2019 B, documented known limitation | no | yes |
| Nitrokey HSM 2 / SmartCard-HSM | no Ed25519 (NXP crypto library) | no | yes |
| TPM 2.0 | no EdDSA in shipping hardware (`TPM_ALG_EDDSA` is only in the registry) | no | yes, digest only |
| OpenPGP cards (YubiKey, Nitrokey 3, Gnuk) | protocol hands the card a digest | n/a | n/a |
| AWS KMS | 4096 B | yes (`ED25519_PH_SHA_512`, 64-byte digest) | yes |
| Google Cloud KMS | pure only, cap undocumented | no | yes |
| Azure Key Vault | no Ed25519 | no | yes |
| Thales Luna (firmware >= 7.4), Entrust nShield | large | yes (`CKM_EDDSA` with `phFlag`) | yes |
| OpenSC PKCS#11 (any card) | dynamic since 0.22; PIV driver has no Ed25519 at all | no | yes |

Two conclusions. First, there is no number that bounds Nix's fingerprint and fits all of these;
the message handed to the device has to be a digest. Second, *Ed25519ph* is the wrong digest
mode to standardise on: no PIV card, no trussed device, no YubiHSM, no GCP implements it. What
every pure-Ed25519 signer does implement is signing a short message. So "hash first, then plain
Ed25519 over the hash" (minisign's choice) is the universal shape; Ed25519ph-capable HSMs can
do that too.

## 4. What works today: ECDSA P-384 on Determinate Nix

Determinate Nix already has a digest-signed algorithm. ECDSA P-384 over SHA-384 is supported by
every PIV card, every HSM, every TPM and every cloud KMS in the table, and the card only sees
48 bytes. The experiment in this repository (README, "P-384 run") does exactly that against the
trussed virtual card: a 700-reference path with a 43 806-byte fingerprint and the real
`emacs-packages-deps` with 48 076 bytes are signed in slot 9C and accepted by Determinate Nix
3.23.1 with `require-sigs`, with `nix store verify`, `copy-sigs` and a fresh-store `nix copy`.
The format matches in both directions: Determinate verifies the card's signatures, and this
repository's independent verifier (`cryptography`) verifies Determinate's software signatures.

The price is the consumer side. The key is `name:base64(SPKI DER)`, which vanilla Nix 2.34,
Lix, snix, attic, harmonia and Determinate Nix *without* `cnsa` all reject as
`public key is not valid`. That is fine for a private cache whose clients are all Determinate
Nix with the flag on, and unusable for anything with a mixed audience. Native signing from the
card also still needs PR 466 (PKCS#11 URIs); today the signing step is this repository's
`nix-piv-sign`, which writes the `Sig:` lines into the narinfos.

## 5. Proposal: an Ed25519 key type that signs a digest

### 5.1 The scheme

A new key type, working name `ed25519-sha256`:

```
message  = fingerprint (unchanged: "1;" + path + ";" + narHash + ";" + narSize + ";" + refs)
digest   = SHA-256("nix-store-path-signature-v1\0" || message)
Sig line = Sig: <key name>:base64(Ed25519_pure_sign(digest))
```

- The fingerprint construction is **not** touched. Everything that already computes it (Nix,
  Lix, snix, go-nix, attic, ...) keeps its code and adds one hash call.
- The device signs 32 bytes with plain Ed25519. Every signer in section 3 that has Ed25519 at
  all can do it, including the solo2 PIV applet, YubiKey, YubiHSM, AWS/GCP KMS and ykcs11.
- The domain-separation prefix makes a digest-mode signature useless as a raw-mode signature
  and vice versa, even for the same key material, and leaves room for a `v2` later.
- SHA-256 rather than SHA-512 because every implementation already has it for `narHash`; the
  32-byte digest is also what PIV P-256 slots and TPMs are used to. (SHA-512 would match
  Ed25519ph's internals but buys nothing: no device in the table turns a 64-byte pure message
  into ph semantics.)

### 5.2 Key encoding

Determinate's convention is "the key blob tells the algorithm". Keep it, and tag the blob:

```
public key : <name>:base64(0x01 || 32-byte Ed25519 public key)      33 bytes
secret key : <name>:base64(0x01 || 64-byte libsodium secret key)    65 bytes
```

Detection stays a size switch: 32/64 = Ed25519 raw, 33/65 with tag `0x01` = Ed25519 over
SHA-256, `0x30...` = DER for the OpenSSL-backed types. Old Nix fails to parse a 33-byte blob
only where an administrator has deliberately put one in `trusted-public-keys`; it never meets
one otherwise, because signatures do not carry the algorithm.

Alternative: `<name>:ed25519-sha256:<base64>`. More readable, but it changes the colon
grammar of `parseColonBase64` and of every third-party key parser, for no gain.

### 5.3 Where Nix changes

Everything is in `libutil`, on top of the shape PR 15926 introduces:

| file | change |
|---|---|
| `src/libutil/include/nix/util/signature/local-keys.hh` | `KeyType::Ed25519Sha256`; `Ed25519Sha256SecretKey` / `Ed25519Sha256PublicKey` subclasses |
| `src/libutil/signature/local-keys.cc` | `SecretKey::parse` / `PublicKey::parse`: the 33/65-byte branch; `generate(KeyType)`; `signDetached` = SHA-256 with prefix, then `crypto_sign_detached`; `verifyDetachedAnon` mirrors it; `to_string` emits the tag byte |
| `src/nix/sigs.cc` | `nix key generate-secret --key-type ed25519-sha256`; `nix store sign` unchanged (it only reads a key file) |
| `src/libutil-tests/local-keys.cc`, `tests/functional/signing.sh` | parse round-trip, known-answer vector, cross-mode rejection, old-key compatibility |
| `doc/manual/source/protocols/binary-cache/narinfo.md`, `doc/manual/source/command-ref/conf-file.md` (`trusted-public-keys`), release notes | document the key type and the digest |

Explicitly **unchanged**: `ValidPathInfo::fingerprint`, `sign`, `checkSignature` in
`src/libstore/path-info.cc`; `Realisation::fingerprint`; `Signer` (`signer.hh`) since the hash
belongs to the key, not the caller; `NarInfo` parsing (`nar-info.cc`); `Store::signPathInfo`
(`store-api.cc`); `getDefaultPublicKeys` (`keys.cc`); the daemon protocol; `nix store copy-sigs`;
`nix store verify`. A path can carry raw-mode and digest-mode signatures side by side under
different key names, which is how a cache migrates.

A PKCS#11 signer for this key type (the PR 466 direction) needs only `CKM_EDDSA` on a 32-byte
message, which ykcs11, OpenSC (OpenPGP driver) and the big HSMs provide.

### 5.4 The same change elsewhere

Each verifier adds one key type and one hash call, roughly 20 lines:
Lix (`libutil/signature`, same code as Nix 2.18), snix `nix-compat::narinfo::VerifyingKey`
(also used by harmonia-style Rust consumers), go-nix `narinfo/signature`, cachix `nix-narinfo`,
attic (`attic/src/signing`), nix-serve-ng, niks3. Until a consumer has it, it ignores the
unknown key in `trusted-public-keys` (or fails to parse it, if it refuses unknown sizes) and
keeps trusting the raw-mode signatures, so dual-signing caches lose nothing.

### 5.5 Security notes

- Collision resistance of SHA-256 is the only new assumption, and the fingerprint already relies
  on it for `narHash`.
- No downgrade path: raw-mode and digest-mode keys have different names and different blobs,
  verification picks the mode from the trusted key, and the domain prefix stops a raw-mode
  signature over a 32-byte string that happens to equal a digest (and the reverse).
- Content-addressed paths bypass signatures entirely in `nix store verify` and `copy`; unchanged.
- Hardware signers produce randomized or deterministic signatures as they like; verification
  does not care. Determinate's software path stays RFC 6979-deterministic.

### 5.6 The alternative that was considered

`2;<path>;<narHash>;<narSize>;sha256(<ref 1>,<ref 2>,...)`, a fingerprint whose reference list
is hashed, stays readable and bounded (~400 bytes) and keeps pure Ed25519. It costs more:
`ValidPathInfo::fingerprint` becomes versioned in `libstore`, every `Sig:` needs to say which
fingerprint it covers (or the key type has to imply it, which is the proposal above with extra
steps), and every downstream verifier reimplements a second string format instead of one hash
call. It also still asks a YubiHSM or trussed device to sign ~400 bytes, which fits today's caps
but not by design. Hashing the whole fingerprint is strictly simpler.

### 5.7 Migration

1. A cache operator generates `cache.example.org-2` as `ed25519-sha256` on the token and
   dual-signs: raw-mode with the existing file key, digest-mode with the token.
2. Clients that have the key type add `cache.example.org-2:...` to `trusted-public-keys`;
   older clients keep verifying `cache.example.org-1`.
3. When the client population allows, the file key is retired.

## 6. Recommendation

Use ECDSA P-384 on Determinate Nix now where the consumer set is closed; it is proven here and
needs no new code. For the ecosystem, propose the `ed25519-sha256` key type on PR 15926: it is
the smallest change that makes hardware-backed signing possible for every Nix implementation
and every Ed25519-capable device, it is the design minisign and OpenPGP already arrived at, and
it leaves the fingerprint, the narinfo format and the daemon protocol alone.
