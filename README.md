# nix-piv

A PIV smartcard as the identity of a Nix build server. One card, three keys:

| slot | key | used for |
|---|---|---|
| 9A | ECDSA P-384 | SSH: nix-daemon to remote builders, `git push` of the build pipeline |
| 9C | ECDSA P-384 | git commit signatures (`gpg.format=ssh`), verified by ftl and comin |
| 9D | ECDSA P-384 | binary cache signatures (Determinate Nix `cnsa`), next to the daemon's own key |

All with PIN policy *once* and touch policy *never*: the server signs unattended. The PIN is
sealed on the server with `systemd-creds` (to the TPM 2.0 when there is one, to the host key
otherwise), so the card unlocks itself after a reboot, a lost card is useless without the
PIN, and no private key ever exists as a file.

Works with any PIV card that has P-384, from the YubiKey 4 on. The tests run on a virtual
card that behaves like a YubiKey 4 (firmware 4.3.7: no GET METADATA, 3DES management key,
no Ed25519).

**Tested on a real YubiKey 4** (firmware 4.3.7, FIDO+CCID mode) on 2026-10-14, with both
provisioning variants (about 5 seconds each). With PIN policy once, touch policy never, and the
PIN fed once to the agent, the card produced SSH signatures from 9A, a git commit signature
from 9C, and ECDSA P-384 cache signatures from 9D (about 330 ms per path, accepted by
Determinate Nix), all unattended, and the agent kept signing across direct card sessions.

## What is in here

| | |
|---|---|
| `nix-piv` | CLI: card info, public keys in every format the setup needs (`pubkeys`), store path signatures (`sign`, `verify`, `fingerprint`) |
| `nix-piv-provision` | provisions a card with keys **generated on the card** (variant B) |
| `nix-piv-seal-pin` | seals the card PIN as a systemd credential |
| `nixosModules.agent` | `services.piv-agent`: an ssh-agent holding the card's keys, unlocked at boot from the sealed PIN, optionally used by nix-daemon |
| `nixosModules.cache-signer` | `services.piv-cache-signer`: a root service that signs a `file://` cache with the 9D key on request |
| `tests/` | a separate flake with the VM tests (`checks.x86_64-linux.builder-{random,mtg}`: the whole chain in two VMs, once per provisioning variant) and the virtual card they use |
| `docs/DESIGN.md` | why store path signatures need a digest for hardware keys, prior art, device limits, the upstream proposal |
| `docs/TPM-Z97.md` | why pavlov's board cannot get a TPM, and how header-only TPM 2.0 modules work elsewhere |

## Provisioning: two variants

Both end with the same card layout and the same server setup; they differ in where the keys
come from and what losing the card means.

| | A: mind-the-gap | B: generated on the card |
|---|---|---|
| keys come from | a BIP-39 mnemonic, derived with argon2id and imported | the card's own random number generator |
| where to run it | the air-gapped mind-the-gap live image | anywhere the card is plugged in |
| lost or broken card | re-run the same command onto a new card: same keys, nothing to change in the fleet | provision a new card, put its new public keys into the fleet config |
| key ever outside the card | yes, briefly, on the air-gapped machine | never |
| management key | 3DES derived from the seed (the card cannot do AES); never stored | random, thrown away |
| re-check later | `mind-the-gap … piv check --pin …` proves every slot holds the derived key | none needed |

### Variant A: mind-the-gap

On the air-gapped machine (mind-the-gap's live image), with the card plugged in:

```sh
mind-the-gap -s '<24 words>' -k pavlov-1 -n 'pavlov builder' \
  piv --algorithm p384 --pin-policy once --touch-policy never --management-key-touch never \
  upload -c <card serial> --pin <new PIN> --yes
```

- `-k pavlov-1` names this generation of keys; a different value gives different keys.
- `--algorithm p384` because the cache key must be ECDSA P-384 for Determinate Nix, and the algorithm
  applies to every slot. nistp384 works for OpenSSH, GitHub and comin.
- `--pin-policy once --touch-policy never`: one PIN per agent session, no button presses.
- `--management-key-touch never`: provisioning happens air-gapped and the derived management
  key never reaches the server, so a touch would only guard against someone who already has
  the seed.
- The PUK is disabled by mind-the-gap; a blocked PIN means re-provisioning from the seed.
- On a YubiKey 4 the management key is 3DES automatically (`--management-key auto`).

To check a card later: the same command with `check --pin <PIN>` instead of `upload …`. On
cards without GET METADATA (YubiKey 4) `check` proves each key with a signature challenge;
the PIN and touch policies cannot be read back on those cards.

Needs mind-the-gap from its `piv-certificate-chain` branch (P-384, 3DES management key,
`--management-key-touch`).

### Variant B: keys generated on the card

```sh
nix-piv-provision --reader 'Yubico YubiKey' --name pavlov-builder
```

It resets the PIV application (all keys on it are lost), generates ECCP384 keys in 9A, 9C
and 9D with PIN once / touch never, writes self-signed certificates (OpenSC and cards without
GET METADATA find the keys through them), asks for a new PIN and PUK, and replaces the
management key with a random one that is not kept: the slots can only change again through
a full reset.

## Server setup

On the build server, with the card plugged in:

```sh
nix-piv pubkeys --principal pavlov-builder --key-name pavlov-card-1
nix-piv-seal-pin            # asks for the PIN, writes /var/lib/piv-agent/pin.cred
```

`pubkeys` prints the four lines the configuration needs:

```
# 9a, SSH (remote builders' authorized_keys, git push deploy key)
ecdsa-sha2-nistp384 AAAA… pavlov-builder
# 9c, git commit signing (user.signingkey for gpg.format=ssh)
key::ecdsa-sha2-nistp384 AAAA…
# 9c, git allowed_signers (ftl verify.allowedSignersFile, comin sshAllowedSignersPath)
pavlov-builder namespaces="git" ecdsa-sha2-nistp384 AAAA…
# 9d, Nix cache key (trusted-public-keys; ecdsa-p384 needs Determinate Nix `cnsa`)
pavlov-card-1:MHYwEAYHKoZIzj0CAQYFK4EEACID…
```

NixOS configuration of the server, here with [ftl](https://github.com/FlorianFranzen/ftl)
as the build pipeline:

```nix
{ config, inputs, ... }: {
  imports = [ inputs.nix-piv.nixosModules.default ];

  services.piv-agent = {
    enable = true;
    user = "ftl";          # the pipeline pushes and signs commits through it
    nixDaemon = true;      # remote builders without sshKey use it too
  };
  services.piv-cache-signer = {
    enable = true;
    cacheDir = "/var/lib/ftl/cache";
    keyName = "pavlov-card-1";
    allowedUser = "ftl";
  };

  ftl.builder = {
    sshAuthSock = config.services.piv-agent.socket;
    deployKeyFile = null;
    signing = { format = "ssh"; key = "key::ecdsa-sha2-nistp384 AAAA…"; };
    cache.signer.command = config.services.piv-cache-signer.requestCommand;
    remoteBuilders.fawkes = {
      enable = true;
      hostName = "fawkes";
      sshUser = "ftl-build";
      sshKey = null;
      publicHostKey = "<base64 of fawkes' ssh_host_ed25519_key.pub>";
    };
  };
}
```

On each remote builder: a user with the 9A key in its `authorized_keys`, listed in
`nix.settings.trusted-users` (ssh-ng builds import unsigned inputs; that makes the user
root-equivalent for the builder's store). On GitHub: the 9A key as a deploy key with write
access on the environment repo. On deployed hosts running comin: the allowed_signers line in
`services.comin.sshAllowedSignersPath` (comin accepts a commit signed by either a GPG key or
an SSH allowed signer, so human GPG-signed commits keep working).

### How the pieces talk

- **piv-agent** runs `ssh-agent` as the agent user and loads the card's keys through OpenSC's
  PKCS#11 module. `piv-agent-unlock` (root) feeds it the PIN from the sealed credential; the
  agent user never sees the PIN. OpenSC is told to reuse that PIN for 9C, which PIV marks as
  "user consent".
- **piv-cache-signer**: the pipeline writes the store paths it pushed to a queue file and runs
  `requestCommand <cache dir> <queue>`, which starts `piv-cache-sign@<queue>.service` through
  polkit (only these units, only for `allowedUser`). The root service signs each path with
  9D; fingerprints come from the local store database, so a queue can only get real store
  paths signed. Paths already carrying the signature are skipped.
- Both share the card. `nix-piv` opens it shared and leaves it powered when done, so cache
  signing and agent signatures interleave (tested on a YubiKey 4). Tools that power the card
  off on disconnect, like `ykman` and pyscard's defaults, end the agent's session with the card:
  after using them on a running server, `systemctl restart piv-agent-unlock`.

### Cache signatures: dual-sign

Only Determinate Nix with `experimental-features = cnsa` verifies ECDSA P-384 store path
signatures; vanilla Nix, Lix and others refuse the key as "not valid". Keep nix-daemon's own
Ed25519 key (`secret-key-files`, ftl's `cache.secretKeyFile`) as well: every path then carries
both signatures, vanilla clients trust the file key, Determinate clients can trust the card.
`docs/DESIGN.md` has the proposal that would let every Nix verify a card-held Ed25519 key.

## Threat model in one table

| | key file | card, PIN typed at boot | card, sealed PIN (this) | card, PIN policy never |
|---|---|---|---|---|
| key copied from disk or backup | lost for good | safe | safe | safe |
| root compromise while running | lost for good | usable only while the attacker holds root | same | same |
| card stolen alone | n/a | safe (3 PIN tries) | safe (3 PIN tries) | usable |
| whole machine stolen and booted | lost | safe | unlocks itself | unlocks itself |
| availability after reboot | automatic | blocked until someone types the PIN | automatic | automatic |

## Tests

The VM tests are a separate flake in `tests/`, so their inputs (the virtual card, mind-the-gap,
Determinate Nix) stay out of the lock files of configurations that use nix-piv:

```sh
cd tests && nix flake check -L --accept-flake-config
```

Two of those inputs (the `feat/version-gating` branch of the piv-authenticator fork and
mind-the-gap's `piv-certificate-chain` branch) are not published yet; until they are, run against the
local checkouts:

```sh
tests/local-overrides.sh flake check -L
tests/local-overrides.sh build .#checks.x86_64-linux.builder-random -L
```

Each `builder-*` test provisions the card (on-card generation or mind-the-gap), reads the
keys back from the certificates, seals the PIN, lets the agent unlock itself, runs a remote
build that the builder's sshd logs under the 9A fingerprint, verifies a 9C-signed commit,
signs a cache push with 9D through the root signer and verifies it with Determinate Nix,
interleaves card sessions, reboots, and pulls the card.
