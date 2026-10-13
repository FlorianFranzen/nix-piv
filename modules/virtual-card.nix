# Tests only. A virtual PIV card on a NixOS machine: pcscd with vsmartcard's vpcd as its reader (a TCP
# listener on localhost:35963, presented to clients as "Virtual PCD 00 00") and the trussed
# piv-authenticator running as a service that connects to it.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.virtual-piv-card;
  readerConfig = ''
    FRIENDLYNAME "Virtual PCD"
    DEVICENAME   /dev/null:0x8C7B
    LIBPATH      ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
    CHANNELID    0x8C7B
  '';
in
{
  options.services.virtual-piv-card = {
    enable = lib.mkEnableOption "a virtual PIV card behind pcscd";
    package = lib.mkOption {
      type = lib.types.package;
      description = "The piv-vpicc package (piv-authenticator's vpicc example).";
    };
    version = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "4.3.7";
      description = ''
        Firmware version the card reports and behaves like (`PIV_VPICC_VERSION`): 4.3.7 has no
        GET METADATA, only a 3DES management key and no Ed25519, like a YubiKey 4. Null keeps
        the card's default (6.6.6, everything enabled).
      '';
    };
    persistent = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Keep the card's keys, PIN and certificates in /var/lib/piv-vpicc across restarts and
        reboots, like a real token. Off: the card is empty after every start.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.pcscd.enable = true;
    services.pcscd.readerConfig = readerConfig;
    # NixOS starts pcscd with -x (exit after 60 s without clients). When it exits, vpcd goes
    # with it, the card process loses its socket and restarts (empty unless persistent). Run
    # pcscd without auto-exit; same command line as the module otherwise.
    systemd.services.pcscd.serviceConfig.ExecStart = lib.mkForce [
      ""
      "${lib.getExe config.services.pcscd.package} -f -c ${pkgs.writeText "reader.conf" readerConfig}"
    ];

    # Restart until the card wins the race with pcscd: vpcd only listens once pcscd has
    # loaded the driver.
    systemd.services.piv-vpicc = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "pcscd.service" ];
      after = [ "pcscd.service" ];
      environment = {
        RUST_LOG = "info";
      } // lib.optionalAttrs cfg.persistent {
        PIV_VPICC_STATE_DIR = "/var/lib/piv-vpicc";
      } // lib.optionalAttrs (cfg.version != null) {
        PIV_VPICC_VERSION = cfg.version;
      };
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/piv-vpicc";
        Restart = "always";
        RestartSec = 1;
      } // lib.optionalAttrs cfg.persistent {
        StateDirectory = "piv-vpicc";
      };
    };
  };
}
