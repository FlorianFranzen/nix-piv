#!/usr/bin/env python3
"""nix-piv: a PIV smartcard as the identity of a Nix build server.

Signs Nix store path fingerprints with a key held in a PIV slot, and prints the public keys
of a provisioned card in the formats the rest of the setup wants (SSH authorized_keys, git
allowed_signers and signing keys, Nix trusted-public-keys).

Nix signs the *fingerprint* of a store path

    1;<store path>;<nar hash, "sha256:" + nix32>;<nar size>;<ref1>,<ref2>,...

and stores the signature as ``Sig: <key name>:<base64>`` in the .narinfo of a binary cache.
Two key types work with a card:

  ecdsa-p384  ECDSA P-384 over SHA-384(fingerprint), DER signature, SPKI public key: the
              `cnsa` experimental feature of Determinate Nix. The card only ever sees the
              48-byte digest, so there is no size limit. Every PIV card since the YubiKey 4.
  ed25519     pure Ed25519 over the raw fingerprint, what every Nix verifies. The card must
              hold the whole fingerprint (see --max-message), and needs Ed25519 in PIV
              (YubiKey 5.7+).

Public keys come from GET METADATA on cards that have it (YubiKey 5.3+) and from the slot's
certificate otherwise, so a card without certificates in its slots only works on 5.3+.
"""

import argparse
import base64
import json
import os
import subprocess
import sys

NIX32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
DEFAULT_READER = os.environ.get("NIX_PIV_READER", "")
PIN_CREDENTIAL = "piv-pin"


# --- Nix -----------------------------------------------------------------------------------

def nix32(data: bytes) -> str:
    """Nix's base32: 5-bit groups taken from the *end* of the byte string."""
    length = (len(data) * 8 - 1) // 5 + 1
    out = []
    for n in range(length - 1, -1, -1):
        b = n * 5
        i, j = divmod(b, 8)
        c = data[i] >> j
        if i + 1 < len(data):
            c |= data[i + 1] << (8 - j)
        out.append(NIX32_ALPHABET[c & 0x1F])
    return "".join(out)


def nar_hash_nix32(sri: str) -> str:
    """'sha256-<base64>' (as `nix path-info --json` prints it) -> 'sha256:<nix32>'."""
    algo, _, b64 = sri.partition("-")
    if algo != "sha256" or not b64:
        raise SystemExit(f"unexpected narHash format: {sri}")
    return f"sha256:{nix32(base64.b64decode(b64))}"


def path_infos(paths):
    """Path info from the local store: the fingerprint is computed from what the store
    database says, never from a narinfo, so only real store paths ever get signed."""
    out = subprocess.run(
        ["nix", "--extra-experimental-features", "nix-command", "path-info", "--json", *paths],
        check=True, capture_output=True, text=True,
    ).stdout
    info = json.loads(out)
    # Nix >= 2.19 keys the object by store path; older versions return a list
    if isinstance(info, list):
        info = {i["path"]: i for i in info}
    return info


def fingerprint(path: str, info: dict) -> str:
    refs = sorted(info["references"])
    return f"1;{path};{nar_hash_nix32(info['narHash'])};{info['narSize']};{','.join(refs)}"


def narinfo_path(cache: str, store_path: str) -> str:
    hash_part = os.path.basename(store_path).split("-", 1)[0]
    return os.path.join(cache, f"{hash_part}.narinfo")


def parse_key(spec: str):
    name, _, b64 = spec.partition(":")
    if not name or not b64:
        raise SystemExit(f"expected <name>:<base64>, got {spec!r}")
    return name, base64.b64decode(b64)


# --- keys ----------------------------------------------------------------------------------

def key_algorithm(public_key) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if isinstance(public_key, Ed25519PublicKey):
        return "ed25519"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384"}.get(
            public_key.curve.name, f"ecdsa-{public_key.curve.name}")
    return type(public_key).__name__


def nix_public_key_bytes(public_key) -> bytes:
    """The bytes Nix base64-encodes after the key name: raw 32 bytes for Ed25519,
    SubjectPublicKeyInfo DER for ECDSA (i2d_PUBKEY in Determinate's local-keys.cc)."""
    from cryptography.hazmat.primitives import serialization
    alg = key_algorithm(public_key)
    if alg == "ed25519":
        return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if alg == "ecdsa-p384":
        return public_key.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    raise SystemExit(f"{alg} keys cannot sign Nix store paths (ed25519 or ecdsa-p384 only)")


def ssh_public_key(public_key) -> str:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.OpenSSH,
                                   serialization.PublicFormat.OpenSSH).decode()


def load_nix_public_key(spec: str):
    """Parse `name:base64` the way Nix does: 32 bytes is Ed25519, anything else is DER SPKI."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    name, raw = parse_key(spec)
    if len(raw) == 32:
        return name, "ed25519", Ed25519PublicKey.from_public_bytes(raw)
    key = serialization.load_der_public_key(raw)
    alg = key_algorithm(key)
    if alg != "ecdsa-p384":
        raise SystemExit(f"{name}: unsupported key type {alg}")
    return name, alg, key


def verify_signature(public_key, algorithm: str, sig: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        if algorithm == "ed25519":
            public_key.verify(sig, message)
        else:
            # Determinate verifies with EVP_DigestVerify(SHA384) over a DER ECDSA-Sig-Value
            public_key.verify(sig, message, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False


# --- PIV -----------------------------------------------------------------------------------

class SharedConnection:
    """A PC/SC connection that shares the card and leaves it as it is when done.

    ykman's own connections try exclusive access first and pyscard powers the card off on
    disconnect (SCARD_UNPOWER_CARD). On a real card that ends every other session with it,
    e.g. the PKCS#11 session of an ssh-agent holding the card's keys, which then refuses to
    sign until the card is added to it again. Shared access and SCARD_LEAVE_CARD avoid that.
    """

    def __init__(self, reader):
        from smartcard.scard import SCARD_LEAVE_CARD, SCARD_SHARE_SHARED
        from yubikit.core import TRANSPORT

        self.connection = reader.createConnection()
        self.connection.connect(mode=SCARD_SHARE_SHARED, disposition=SCARD_LEAVE_CARD)
        atr = self.connection.getATR()
        self.transport = TRANSPORT.USB if atr and atr[1] & 0xF0 == 0xF0 else TRANSPORT.NFC

    def send_and_receive(self, apdu):
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        return bytes(data), sw1 << 8 | sw2

    def close(self):
        self.connection.disconnect()
        if hasattr(self.connection, "release"):
            self.connection.release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_piv(reader: str):
    """Open the first reader matching `reader` that holds a PIV card."""
    from smartcard.System import readers
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import PivSession

    # PivSession only needs the SmartCardConnection interface
    SmartCardConnection.register(SharedConnection)

    errors = []
    for r in readers():
        if reader.lower() not in str(r).lower():
            continue
        try:
            conn = SharedConnection(r)
        except Exception as err:  # empty reader, ...
            errors.append(f"{r}: {err}")
            continue
        try:
            return PivSession(conn), conn
        except Exception as err:
            conn.close()
            errors.append(f"{r}: {err}")
    detail = "; ".join(errors) or "no readers"
    raise SystemExit(f"no PIV card in a reader matching {reader!r} ({detail})")


def has_metadata(piv) -> bool:
    return tuple(piv.version) >= (5, 3, 0)


def slot_public_key(piv, slot):
    """The slot's public key: GET METADATA where the card has it, else the slot certificate."""
    if has_metadata(piv):
        try:
            return piv.get_slot_metadata(slot).public_key
        except Exception:
            pass  # empty slot or no metadata after all: try the certificate
    try:
        return piv.get_certificate(slot).public_key()
    except Exception as err:
        raise SystemExit(f"slot {slot:02X}: no key readable (no metadata on this card, and no "
                         f"certificate in the slot: {err})")


def read_pin(args) -> str:
    if getattr(args, "pin_file", None):
        with open(args.pin_file) as f:
            return f.read().strip()
    creds = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds and os.path.exists(os.path.join(creds, PIN_CREDENTIAL)):
        with open(os.path.join(creds, PIN_CREDENTIAL)) as f:
            return f.read().strip()
    if os.environ.get("PIV_PIN"):
        return os.environ["PIV_PIN"]
    raise SystemExit("no PIN: pass --pin-file, set PIV_PIN, or run with the "
                     f"'{PIN_CREDENTIAL}' credential")


def slot_arg(text: str):
    from yubikit.piv import SLOT
    return SLOT(int(text, 16))


# --- commands ------------------------------------------------------------------------------

def cmd_fingerprint(args):
    infos = path_infos(args.paths)
    for p in args.paths:
        print(fingerprint(p, infos[p]))


def cmd_verify(args):
    """Like Nix: a path is good if *any* signature by the trusted key verifies."""
    name, algorithm, key = load_nix_public_key(args.public_key)
    infos = path_infos(args.paths)
    ok = True
    for p in args.paths:
        fp = fingerprint(p, infos[p]).encode()
        sigs = [s for s in infos[p].get("signatures", []) if s.startswith(name + ":")]
        good = sum(verify_signature(key, algorithm, base64.b64decode(s.split(":", 1)[1]), fp)
                   for s in sigs)
        if good:
            print(f"{p}: {good} {algorithm} signature(s) by {name} verify")
        else:
            print(f"{p}: no valid signature by {name}")
            ok = False
    sys.exit(0 if ok else 1)


def cmd_info(args):
    piv, conn = open_piv(args.reader)
    try:
        print(f"version:  {'.'.join(map(str, piv.version))}")
        try:
            print(f"serial:   {piv.get_serial()}")
        except Exception as err:
            print(f"serial:   n/a ({err})")
        if has_metadata(piv):
            mk = piv.get_management_key_metadata()
            print(f"mgmt key: {mk.key_type.name}, default={mk.default_value}, "
                  f"touch={mk.touch_policy.name}")
        else:
            print("mgmt key: no metadata on this card (3DES on a YubiKey 4)")
        for name in ("9a", "9c", "9d", "9e"):
            slot = slot_arg(name)
            try:
                key = slot_public_key(piv, slot)
                line = key_algorithm(key)
                if has_metadata(piv):
                    m = piv.get_slot_metadata(slot)
                    line += f", pin={m.pin_policy.name}, touch={m.touch_policy.name}"
                print(f"slot {name}:  {line}")
            except SystemExit:
                print(f"slot {name}:  empty")
    finally:
        conn.close()


def format_key(public_key, fmt: str, key_name: str, principal: str) -> str:
    if fmt == "nix":
        return f"{key_name}:{base64.b64encode(nix_public_key_bytes(public_key)).decode()}"
    if fmt == "ssh":
        return f"{ssh_public_key(public_key)} {principal}"
    if fmt == "signingkey":
        return f"key::{ssh_public_key(public_key)}"
    if fmt == "allowed-signers":
        return f'{principal} namespaces="git" {ssh_public_key(public_key)}'
    if fmt == "pem":
        from cryptography.hazmat.primitives import serialization
        return public_key.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo).decode().strip()
    raise SystemExit(f"unknown format {fmt}")


def cmd_public_key(args):
    piv, conn = open_piv(args.reader)
    try:
        key = slot_public_key(piv, slot_arg(args.slot))
    finally:
        conn.close()
    print(format_key(key, args.format, args.key_name, args.principal))


def cmd_pubkeys(args):
    """Everything the NixOS side needs from a provisioned build-server card."""
    piv, conn = open_piv(args.reader)
    try:
        keys = {name: slot_public_key(piv, slot_arg(name)) for name in ("9a", "9c", "9d")}
    finally:
        conn.close()
    print(f"# 9a, SSH (remote builders' authorized_keys, git push deploy key)")
    print(format_key(keys["9a"], "ssh", args.cache_key_name, args.principal))
    print(f"# 9c, git commit signing (user.signingkey for gpg.format=ssh)")
    print(format_key(keys["9c"], "signingkey", args.cache_key_name, args.principal))
    print(f"# 9c, git allowed_signers (ftl verify.allowedSignersFile, comin sshAllowedSignersPath)")
    print(format_key(keys["9c"], "allowed-signers", args.cache_key_name, args.principal))
    print(f"# 9d, Nix cache key (trusted-public-keys; ecdsa-p384 needs Determinate Nix `cnsa`)")
    try:
        print(format_key(keys["9d"], "nix", args.cache_key_name, args.principal))
    except SystemExit as err:
        print(f"# not usable for Nix signatures: {err}")


def cmd_sign(args):
    from cryptography.hazmat.primitives import hashes

    paths = list(args.paths)
    if args.paths_from:
        with open(args.paths_from) as f:
            paths += [line.strip() for line in f if line.strip()]
    paths = list(dict.fromkeys(paths))  # keep order, drop duplicates
    if args.cache:
        # A pipeline hands over whole closures every run: skip what already carries our
        # signature (each card signature costs a few hundred milliseconds on a YubiKey 4)
        # and what is not in the cache at all
        todo = []
        for p in paths:
            ni = narinfo_path(args.cache, p)
            if not os.path.exists(ni):
                print(f"{p}: not in {args.cache}, skipped", file=sys.stderr)
                continue
            with open(ni) as f:
                if any(line.startswith(f"Sig: {args.key_name}:") for line in f):
                    continue
            todo.append(p)
        print(f"# {len(todo)} of {len(paths)} path(s) need a signature", file=sys.stderr)
        paths = todo
    if not paths:
        print("nothing to sign", file=sys.stderr)
        return
    infos = path_infos(paths)

    slot = slot_arg(args.slot)
    piv, conn = open_piv(args.reader)
    try:
        public_key = slot_public_key(piv, slot)
        algorithm = key_algorithm(public_key)
        if algorithm not in ("ed25519", "ecdsa-p384"):
            raise SystemExit(f"slot {args.slot}: {algorithm} cannot sign Nix store paths")
        if args.algorithm != "auto" and args.algorithm != algorithm:
            raise SystemExit(f"slot {args.slot} holds {algorithm}, not {args.algorithm}")
        if algorithm == "ed25519":
            # The card signs the whole fingerprint as one message; trussed apps panic past
            # MAX_MESSAGE_LENGTH (1024, or 2048), other cards answer 6700. Refuse up front.
            too_long = {p: len(fingerprint(p, infos[p])) for p in paths
                        if len(fingerprint(p, infos[p])) > args.max_message}
            for p, n in too_long.items():
                print(f"{p}: fingerprint is {n} bytes, over --max-message {args.max_message} "
                      f"({len(infos[p]['references'])} references)", file=sys.stderr)
            if too_long:
                raise SystemExit("refusing to send a fingerprint the card cannot hold "
                                 "(ecdsa-p384 has no such limit)")
        from yubikit.piv import KEY_TYPE
        key_type = KEY_TYPE.ED25519 if algorithm == "ed25519" else KEY_TYPE.ECCP384
        pin = read_pin(args)
        print(f"# public key: {format_key(public_key, 'nix', args.key_name, '')}", file=sys.stderr)
        for p in paths:
            fp = fingerprint(p, infos[p])
            # PIN policy ALWAYS needs a VERIFY right before every signature; ONCE does not
            # mind, and other sessions (SELECT) may have reset the state in between
            piv.verify_pin(pin)
            if algorithm == "ed25519":
                sig = piv.sign(slot, key_type, fp.encode(), None)
            else:
                # yubikit hashes with SHA-384 and sends the 48-byte digest; the card answers
                # with a DER ECDSA-Sig-Value, which is exactly what Determinate stores
                sig = piv.sign(slot, key_type, fp.encode(), hashes.SHA384())
            if not verify_signature(public_key, algorithm, sig, fp.encode()):
                raise SystemExit(f"{p}: the card's signature does not verify")
            line = f"Sig: {args.key_name}:{base64.b64encode(sig).decode()}"
            print(f"{p} ({len(fp)}-byte fingerprint)\n  {line}")
            if args.cache:
                ni = narinfo_path(args.cache, p)
                with open(ni, "r+") as f:
                    body = f.read()
                    if f"StorePath: {p}\n" not in body:
                        raise SystemExit(f"{ni} is not the narinfo of {p}")
                    if line not in body.splitlines():
                        if not body.endswith("\n"):
                            f.write("\n")
                        f.write(line + "\n")
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(prog="nix-piv", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("fingerprint", help="print the fingerprint Nix signs (no card)")
    s.add_argument("paths", nargs="+")
    s.set_defaults(func=cmd_fingerprint)

    s = sub.add_parser("verify", help="verify local-store signatures against the fingerprint")
    s.add_argument("--public-key", required=True, help="<name>:<base64>, as in trusted-public-keys")
    s.add_argument("paths", nargs="+")
    s.set_defaults(func=cmd_verify)

    def reader_opt(s):
        s.add_argument("--reader", default=DEFAULT_READER,
                       help="PC/SC reader name substring (default: $NIX_PIV_READER or any)")

    def naming_opts(s):
        s.add_argument("--key-name", "--cache-key-name", dest="key_name", default="nix-piv-1",
                       help="Nix key name (default: nix-piv-1)")
        s.add_argument("--principal", default="builder",
                       help="SSH comment / allowed_signers principal (default: builder)")

    s = sub.add_parser("info", help="card version, serial, slots")
    reader_opt(s)
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("public-key", help="print one slot's public key")
    reader_opt(s)
    naming_opts(s)
    s.add_argument("--slot", default="9d", help="PIV slot, hex (default: 9d)")
    s.add_argument("--format", default="nix",
                   choices=["nix", "ssh", "signingkey", "allowed-signers", "pem"])
    s.set_defaults(func=cmd_public_key)

    s = sub.add_parser("pubkeys", help="print 9a/9c/9d in every format the setup needs")
    reader_opt(s)
    naming_opts(s)
    s.set_defaults(func=cmd_pubkeys, cache_key_name=None)

    s = sub.add_parser("sign", help="sign store paths with a slot key")
    reader_opt(s)
    naming_opts(s)
    s.add_argument("--slot", default="9d", help="PIV slot, hex (default: 9d)")
    s.add_argument("--algorithm", choices=["auto", "ed25519", "ecdsa-p384"], default="auto",
                   help="expected key type (default: whatever the slot holds)")
    s.add_argument("--pin-file", help=f"file with the PIN (default: the '{PIN_CREDENTIAL}' "
                                      "systemd credential, then $PIV_PIN)")
    s.add_argument("--cache", help="binary cache directory whose .narinfo files get the Sig: lines")
    s.add_argument("--paths-from", help="file with one store path per line (added to PATHS)")
    s.add_argument("--max-message", type=int, default=1024,
                   help="largest fingerprint the card takes in one GENERAL AUTHENTICATE "
                        "(ed25519 only; default 1024)")
    s.add_argument("paths", nargs="*")
    s.set_defaults(func=cmd_sign)

    args = ap.parse_args()
    if args.cmd == "pubkeys":
        args.cache_key_name = args.key_name
    args.func(args)


if __name__ == "__main__":
    main()
