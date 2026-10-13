# An ssh-agent holding the keys of a PIV card, unlocked at boot from a sealed PIN.
#
# The agent runs as `user` (so that user's services, e.g. a build pipeline, can push and sign
# commits through it; root can always connect). It loads the card's keys through OpenSC's
# PKCS#11 module. A root oneshot unlocks it with the PIN from a systemd credential sealed by
# `nix-piv-seal-pin` (systemd-creds --with-key=auto), so the PIN never reaches `user`.
# With `nixDaemon`, nix-daemon gets the agent's socket and remote builders need no key file.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.piv-agent;
  socketDir = dirOf cfg.socket;

  # The PIN reaches ssh-add through SSH_ASKPASS, read from the credential systemd decrypted
  # for this one service run
  askpass = pkgs.writeShellScript "piv-agent-askpass" ''
    exec ${pkgs.coreutils}/bin/cat "$CREDENTIALS_DIRECTORY/piv-pin"
  '';

  # PIV marks the digital signature slot (9C) as "user consent": OpenSC would demand the PIN
  # again for every signature, which an unattended agent cannot answer. Let it reuse the
  # PIN it was unlocked with; the card's own PIN policy (ONCE) is what applies.
  openscConf = pkgs.writeText "opensc-piv-agent.conf" ''
    app default {
      framework pkcs15 {
        pin_cache_ignore_user_consent = true;
      }
    }
  '';
in
{
  options.services.piv-agent = {
    enable = lib.mkEnableOption "an ssh-agent backed by a PIV card";

    user = lib.mkOption {
      type = lib.types.str;
      default = "piv-agent";
      description = ''
        User the agent runs as. Its socket is only reachable by this user and root. A user
        of this name is created unless it is defined elsewhere.
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = cfg.user;
      description = "Group of the agent user (created with it).";
    };

    socket = lib.mkOption {
      type = lib.types.str;
      default = "/run/piv-agent/agent.sock";
      description = "Path of the agent socket (`SSH_AUTH_SOCK`).";
    };

    pinCredential = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/piv-agent/pin.cred";
      description = ''
        Encrypted systemd credential named `piv-pin` holding the card PIN, as written by
        `nix-piv-seal-pin`. The unlock service is skipped while it does not exist.
      '';
    };

    pkcs11Module = lib.mkOption {
      type = lib.types.str;
      default = "${pkgs.opensc}/lib/opensc-pkcs11.so";
      defaultText = lib.literalExpression ''"''${pkgs.opensc}/lib/opensc-pkcs11.so"'';
      description = "PKCS#11 module the agent loads the card's keys through.";
    };

    nixDaemon = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Give nix-daemon the agent socket, so `nix.buildMachines` entries without `sshKey`
        authenticate with the card.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.pcscd.enable = true;
    environment.systemPackages = [ pkgs.opensc pkgs.yubikey-manager ];

    users.users = lib.mkIf (cfg.user == "piv-agent") {
      piv-agent = {
        isSystemUser = true;
        group = cfg.group;
      };
    };
    users.groups = lib.mkIf (cfg.user == "piv-agent") { ${cfg.group} = { }; };

    # pcsc-lite asks polkit whether a client may talk to readers and cards; let the agent user
    security.polkit.extraConfig = lib.mkIf (cfg.user != "root") ''
      polkit.addRule(function(action, subject) {
        if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
             action.id == "org.debian.pcsc-lite.access_card") &&
            subject.user == "${cfg.user}") {
          return polkit.Result.YES;
        }
      });
    '';

    systemd.services.piv-agent = {
      description = "ssh-agent backed by a PIV card";
      wantedBy = [ "multi-user.target" ];
      after = [ "pcscd.socket" ];
      environment.OPENSC_CONF = openscConf;
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        # store paths are refused as PKCS#11 providers unless allow-listed with -P
        ExecStart = "${pkgs.openssh}/bin/ssh-agent -D -a ${cfg.socket} -P ${cfg.pkcs11Module}";
        ExecStartPre = "${pkgs.coreutils}/bin/rm -f ${cfg.socket}";
        RuntimeDirectory = lib.mkIf (socketDir == "/run/piv-agent") "piv-agent";
        Restart = "on-failure";
      };
    };

    systemd.services.piv-agent-unlock = {
      description = "Unlock the PIV agent with the sealed PIN";
      # started with the agent, and again whenever the agent restarts
      wantedBy = [ "piv-agent.service" ];
      bindsTo = [ "piv-agent.service" ];
      after = [ "piv-agent.service" "pcscd.socket" ];
      unitConfig.ConditionPathExists = cfg.pinCredential;
      path = [ pkgs.openssh pkgs.coreutils ];
      environment = {
        SSH_AUTH_SOCK = cfg.socket;
        SSH_ASKPASS = askpass;
        SSH_ASKPASS_REQUIRE = "force";
        DISPLAY = ":0";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        LoadCredentialEncrypted = "piv-pin:${cfg.pinCredential}";
      };
      script = ''
        # the agent socket and the card may come up a moment after this unit
        for _ in $(seq 60); do
          [ -S ${cfg.socket} ] && ssh-keygen -D ${cfg.pkcs11Module} >/dev/null 2>&1 && break
          sleep 1
        done
        ssh-add -e ${cfg.pkcs11Module} 2>/dev/null || true
        ssh-add -s ${cfg.pkcs11Module} < /dev/null
        ssh-add -l
      '';
    };

    systemd.services.nix-daemon.environment = lib.mkIf cfg.nixDaemon {
      SSH_AUTH_SOCK = cfg.socket;
    };
  };
}
