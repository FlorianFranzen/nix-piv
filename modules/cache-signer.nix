# Sign binary cache narinfos with a PIV slot key (9D by default), as root.
#
# A cache writer that must not hold the PIN itself (e.g. a build pipeline running as its own
# user) lists the store paths it pushed in a file and starts
#   systemctl start --wait piv-cache-sign@$(systemd-escape --path /path/to/queue).service
# polkit lets `allowedUser` start exactly these units. The service signs every listed path
# with `nix-piv sign`; fingerprints come from the local store database, so a queue file can
# only get real store paths signed, never invented ones, and only into `cacheDir`.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.piv-cache-signer;
  nix-piv = pkgs.callPackage ../pkgs/nix-piv.nix { src = ../nix_piv.py; };
in
{
  options.services.piv-cache-signer = {
    enable = lib.mkEnableOption "PIV-card signatures for a file:// binary cache";

    cacheDir = lib.mkOption {
      type = lib.types.str;
      description = "Binary cache directory whose .narinfo files get the card's `Sig:` lines.";
    };

    keyName = lib.mkOption {
      type = lib.types.str;
      example = "pavlov-card-1";
      description = "Nix key name the signatures carry (the part before `:` in trusted-public-keys).";
    };

    slot = lib.mkOption {
      type = lib.types.str;
      default = "9d";
      description = "PIV slot holding the signing key (ECDSA P-384 for Determinate Nix, or Ed25519).";
    };

    reader = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "PC/SC reader name substring; empty takes the first reader with a PIV card.";
    };

    pinCredential = lib.mkOption {
      type = lib.types.str;
      default = config.services.piv-agent.pinCredential;
      defaultText = lib.literalExpression "config.services.piv-agent.pinCredential";
      description = "Encrypted systemd credential `piv-pin` with the card PIN (see `nix-piv-seal-pin`).";
    };

    allowedUser = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "User allowed to start `piv-cache-sign@<queue>.service` through polkit.";
    };

    requestCommand = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = toString (pkgs.writeShellScript "piv-cache-sign-request" ''
        # usage: piv-cache-sign-request CACHE_DIR QUEUE_FILE
        # (the cache directory is fixed by the signer service; it is accepted for the
        # interface of ftl's cache.signer.command and must match)
        if [ "$1" != ${lib.escapeShellArg cfg.cacheDir} ]; then
          echo "piv-cache-signer signs into ${cfg.cacheDir}, not $1" >&2
          exit 1
        fi
        unit="piv-cache-sign@$(${pkgs.systemd}/bin/systemd-escape --path "$2").service"
        exec ${pkgs.systemd}/bin/systemctl start --wait "$unit"
      '');
      defaultText = lib.literalMD "a script starting `piv-cache-sign@<queue>.service`";
      description = ''
        Command for cache writers: `<command> <cache dir> <queue file>` starts the signer
        on the queue and waits for it (e.g. ftl's `cache.signer.command`).
      '';
    };

    afterSign = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Shell commands run after signing (e.g. re-unlocking an agent sharing the card).";
    };
  };

  config = lib.mkIf cfg.enable {
    services.pcscd.enable = true;
    environment.systemPackages = [ nix-piv ];

    systemd.services."piv-cache-sign@" = {
      description = "Sign the store paths listed in %f into the binary cache with the PIV card";
      after = [ "pcscd.socket" ];
      path = [ config.nix.package nix-piv ];
      serviceConfig = {
        Type = "oneshot";
        LoadCredentialEncrypted = "piv-pin:${cfg.pinCredential}";
      };
      environment.NIX_PIV_READER = cfg.reader;
      scriptArgs = "%f";
      script = ''
        queue="$1"
        nix-piv sign --slot ${cfg.slot} --key-name ${lib.escapeShellArg cfg.keyName} \
          --cache ${lib.escapeShellArg cfg.cacheDir} --paths-from "$queue"
        ${cfg.afterSign}
      '';
    };

    security.polkit.extraConfig = lib.mkIf (cfg.allowedUser != null) ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" &&
            subject.user == "${cfg.allowedUser}" &&
            action.lookup("verb") == "start" &&
            /^piv-cache-sign@.+\.service$/.test(action.lookup("unit"))) {
          return polkit.Result.YES;
        }
      });
    '';
  };
}
