# Provision a build-server card with keys generated *on* the card (the variant without
# mind-the-gap): ECCP384 in 9A (SSH), 9C (git signing) and 9D (Nix cache), PIN once /
# touch never, self-signed certificates (OpenSC and cards without GET METADATA need them),
# a new PIN and PUK, and a random management key that is thrown away.
{ writeShellApplication, yubikey-manager, openssl, nix-piv }:

writeShellApplication {
  name = "nix-piv-provision";
  runtimeInputs = [ yubikey-manager openssl nix-piv ];
  text = ''
    usage() {
      cat <<USAGE
    usage: nix-piv-provision --reader NAME --name CN [--pin PIN] [--puk PUK] [--yes]

    Resets the PIV application of the card in reader NAME (all keys and certificates are
    lost), then generates ECCP384 keys in 9A, 9C and 9D with PIN policy ONCE and touch policy
    NEVER, writes self-signed certificates (CN=<CN> <slot>), sets the PIN and PUK, and
    replaces the management key with a random one that is not kept: the slots can only be
    changed again by a full reset.
    PIN and PUK are asked for when not given (or taken from \$PIV_PIN / \$PIV_PUK).
    USAGE
    }

    reader="" name="" pin="''${PIV_PIN:-}" puk="''${PIV_PUK:-}" yes=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --reader) reader="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --pin) pin="$2"; shift 2 ;;
        --puk) puk="$2"; shift 2 ;;
        --yes) yes=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [ -n "$reader" ] && [ -n "$name" ] || { usage >&2; exit 2; }
    if [ -z "$pin" ]; then read -r -s -p "New PIN (6-8 characters): " pin; echo; fi
    if [ -z "$puk" ]; then read -r -s -p "New PUK (6-8 characters): " puk; echo; fi
    case "''${#pin}" in 6|7|8) ;; *) echo "PIN must have 6 to 8 characters" >&2; exit 2 ;; esac
    case "''${#puk}" in 6|7|8) ;; *) echo "PUK must have 6 to 8 characters" >&2; exit 2 ;; esac

    if [ -z "$yes" ]; then
      read -r -p "Reset the PIV application in '$reader' and lose all its keys? [y/N] " answer
      [ "$answer" = y ] || exit 1
    fi

    ykman() { command ykman --reader "$reader" "$@"; }
    default_mgmt=010203040506070801020304050607080102030405060708
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

    ykman piv reset --force
    ykman piv access change-pin --pin 123456 --new-pin "$pin"
    ykman piv access change-puk --puk 12345678 --new-puk "$puk"

    for slot in 9a 9c 9d; do
      ykman piv keys generate --algorithm ECCP384 --pin-policy ONCE --touch-policy NEVER \
        --management-key "$default_mgmt" "$slot" "$tmp/$slot.pem"
      ykman piv certificates generate --management-key "$default_mgmt" --pin "$pin" \
        --subject "CN=$name $slot" --valid-days 36500 "$slot" "$tmp/$slot.pem"
    done

    # Last, so everything above could use the default key: a random management key that is
    # not stored anywhere. Nobody can change the slots afterwards short of a full reset,
    # which destroys the keys; the certificates are valid for 100 years. (TDES on cards
    # without AES support, e.g. YubiKey 4; ykman picks the card's default algorithm.)
    ykman piv access change-management-key --management-key "$default_mgmt" \
      --generate --force >/dev/null

    nix-piv pubkeys --reader "$reader" --principal "$name"
  '';
}
