# Handover

This is for whoever reviews or tests nix-piv: what is in the repository,
how to run its tests, where to look hardest, and what is left. README.md is
the user's view; docs/DESIGN.md the case for digest signatures in Nix.

State as of 2026-10-24. `git log --oneline @{u}..` shows what is not
pushed; check it before relying on anything below.

## The repositories around it

| Repository | Path | What it has to do with nix-piv |
|---|---|---|
| nix-piv | `~/Nix/nix-piv` | This one, `main`, published at `github:FlorianFranzen/nix-piv`. |
| ftl | `~/Nix/ftl` | The fleet library. `fleet.smartcard` enables `services.piv-agent` on headless hosts and wires `fleet.builder` to its shared socket (ftl's `HUMAN.md`, "Smartcards, AGENTS.md, ssh and Nix trust"). |
| nixrc (piv-builder) | `~/Nix/nixrc-piv-builder` | The workstations' fleet, branch `piv-builder`: pavlov as the card-backed build server (`nixos/services/forge`, staged, not committed). |
| mind-the-gap | `~/Glial/mind-the-gap` | Provisioning variant A (keys derived from a seed). Published at `github:gliology/mind-the-gap`; the tests use its `piv-certificate-chain` branch. |
| piv-authenticator fork | `~/Gli.al/piv-authenticator-version-gating` | The virtual card of the tests, branch `feat/version-gating` (behaves like the firmware version it reports). **Not pushed**, so the tests need the local checkout. |

## What is in it

| Piece | File | In short |
|---|---|---|
| `nix-piv` | `nix_piv.py`, `pkgs/nix-piv.nix` | CLI over pyscard/yubikit: `info`, `pubkeys` (every format the setup needs), `sign`/`verify`/`fingerprint` of store paths with 9D. Opens the card shared and leaves it powered (`SCARD_LEAVE_CARD`), so it does not end the agent's session. |
| `nix-piv-provision` | `pkgs/nix-piv-provision.nix` | Variant B: resets PIV, generates P-384 keys in 9A/9C/9D with PIN once / touch never, self-signed certificates, new PIN and PUK, a random management key that is thrown away. |
| `nix-piv-seal-pin` | `pkgs/nix-piv-seal-pin.nix` | `systemd-creds encrypt --with-key=auto` of the PIN into `/var/lib/piv-agent/pin.cred` (TPM 2.0 when present, else the host key). |
| `services.piv-agent` | `modules/agent.nix` | `ssh-agent` as the agent user with OpenSC's PKCS#11 module; `piv-agent-unlock` (root) feeds it the sealed PIN through `SSH_ASKPASS`; `nixDaemon` gives nix-daemon the socket. `accessGroup` adds `sharedSocket`, a root-owned `0660` socket for that group, forwarded by `systemd-socket-proxyd` running as the agent user (ssh-agent itself refuses every uid but its own and root). |
| `services.piv-cache-signer` | `modules/cache-signer.nix` | `piv-cache-sign@<queue>` (root) signs the paths of a queue file in a `file://` cache with 9D; `allowedUser` may start only those units (polkit). `requestCommand` is what ftl's `cache.signer.command` calls. |
| VM tests | `tests/` | A separate flake (so its inputs stay out of consumers' locks): the virtual card (`virtual-card.nix`, `piv-vpicc.nix`), the end-to-end test (`builder.nix`). |

## Testing

### Prerequisites

- Nix with flakes, KVM, about 4 GB of RAM for the two VMs.
- `--accept-flake-config` (or the same substituter in your nix.conf): the
  tests use Determinate Nix, the only Nix that verifies ECDSA P-384 store
  path signatures, from `install.determinate.systems`.
- The piv-authenticator fork checked out (see above). The first run builds
  the virtual card from Rust sources and takes a while.

### Running them

```sh
cd ~/Nix/nix-piv
tests/local-overrides.sh build .#checks.x86_64-linux.builder-random -L --no-link
tests/local-overrides.sh build .#checks.x86_64-linux.builder-mtg -L --no-link
```

`local-overrides.sh` points the test flake at the local piv-authenticator
(`$PIV_AUTHENTICATOR`) instead of its GitHub URL; mind-the-gap comes from
its `piv-certificate-chain` branch on GitHub. To test a local mind-the-gap,
name the branch, since the variant needs that branch's CLI (`-k`,
`--pin-policy`, `--management-key-touch`):
`MIND_THE_GAP="$HOME/Glial/mind-the-gap?ref=piv-certificate-chain"`. The
script does not write a lock file.

Both checks passed on 2026-10-24, `builder-mtg` against mind-the-gap
`a773b20` (`piv-certificate-chain`). Against mind-the-gap's `v1` branch it
fails at provisioning (`unexpected argument '-k'`): the test follows the
older CLI.

| Check | Provisioning | Covers |
|---|---|---|
| `builder-random` | `nix-piv-provision` (keys made on the card) | The whole chain, below. |
| `builder-mtg` | mind-the-gap `piv … upload` (keys from a seed), then `piv … check` | The same chain with imported keys. |

The chain, in two VMs (a server with the virtual YubiKey 4, a remote
builder):
- the card reports firmware 4.3.7 and refuses Ed25519 (like a YubiKey 4);
- provisioning, then `nix-piv info`/`pubkeys` read the keys back from the
  slot certificates;
- the PIN is sealed, the pipeline user cannot read the credential, the
  agent unlocks itself;
- members of `accessGroup` list the keys through the shared socket; others,
  and members on the agent's own socket, are refused;
- a remote build over ssh-ng, logged by the builder's sshd under the 9A
  fingerprint;
- a 9C-signed git commit, verified against allowed_signers;
- a cache push signed with 9D through the root signer, verified by
  Determinate Nix and refused by plain Nix; the pipeline user cannot start
  `piv-agent-unlock`;
- the agent still signs after the signer used the card;
- a reboot: the agent unlocks itself and builds resume;
- the card pulled: builds fail; back in, they work again.

If a test fails, `nix log <drv>` has the whole run; `!!!` marks the failing
subtest.

### On real hardware

Tested on a YubiKey 4 (firmware 4.3.7) on 2026-10-14, both variants; the
README has the numbers. To repeat it on a spare card (provisioning resets
it): provision with either variant, `nix-piv pubkeys`, `nix-piv-seal-pin`,
`systemctl restart piv-agent`, then `SSH_AUTH_SOCK=/run/piv-agent/agent.sock
ssh-add -l`. Never run the provisioning against a card by "whatever is
plugged in": name it by its reader or serial.

## Reviewing the code

### Where the risk is

- **The PIN.** It exists in plaintext only inside `piv-agent-unlock`'s run
  (`$CREDENTIALS_DIRECTORY`) and inside the agent's PKCS#11 session. Check
  that no unit, log line or file outside that hands it to the agent user or
  the pipeline user. `LoadCredentialEncrypted` and `SSH_ASKPASS` are the
  only paths.
- **What the cache signer will sign.** It fingerprints paths from the local
  store database, never from the queue file's contents, so a queue can only
  get real store paths signed. The polkit rule must let `allowedUser` start
  `piv-cache-sign@*.service` and nothing else.
- **The shared socket.** Root-owned, `0660`, group `accessGroup`; the proxy
  runs as the agent user, so ssh-agent sees that uid. Members can make the
  card sign (that is the purpose), never read a key. Who is in the group is
  the whole access control.
- **`pin_cache_ignore_user_consent`.** OpenSC is told to reuse the session
  PIN for 9C, which PIV marks as "user consent". This is what makes
  unattended commit signing work; it is right only because the card's own
  PIN policy is *once*.
- **Card sessions.** Everything in nix-piv connects shared and leaves the
  card powered. Tools that power it off (`ykman`, pyscard's default) end the
  agent's session; `systemctl restart piv-agent-unlock` recovers. The
  virtual card never showed this; only a real YubiKey did.

### Known limitations

- Only Determinate Nix (`cnsa`) verifies the P-384 cache signatures; keep
  nix-daemon's own Ed25519 key too (dual-sign, README). docs/DESIGN.md is
  the proposal that would let every Nix verify a card-held key.
- 9D's certificate is key-agreement only, yet it signs store paths; Nix
  does not look at the certificate. Open.
- pavlov's board has no TPM (docs/TPM-Z97.md): its PIN is sealed to the host
  key, so a stolen and booted machine unlocks itself (the threat model table
  in the README).
- The test flake has no lock file, and one of its inputs is unpushed.

## Remaining steps

1. Push the piv-authenticator fork's `feat/version-gating` branch, then
   lock the test flake (`cd tests && nix flake lock --accept-flake-config`)
   and commit the lock, so the tests run without `local-overrides.sh`.
2. In nixrc: lock this repository, add `nix-piv.nixosModules.agent` (or
   `default`) to `nixos.sharedModules`, and let ftl's `fleet.smartcard`
   (pavlov headless) enable the agent; drop the hand-written
   `services.piv-agent` settings.
3. Provision pavlov's card, seal its PIN, put its public keys into the
   fleet (README, "Server setup").
