# A build server whose identity is a YubiKey-4-like PIV card, end to end, in two VMs.
#
# server ("pavlov"): the virtual card reporting firmware 4.3.7 (no GET METADATA, 3DES
#   management key, no Ed25519), persistent across reboots; services.piv-agent running as the
#   pipeline user `ftl` with nixDaemon; services.piv-cache-signer for a file:// cache.
# builder ("fawkes"): sshd + Nix, user `ftl-build` trusted.
#
# Provisioning, chosen by `variant`:
#   random  nix-piv-provision: keys generated on the card
#   mtg     mind-the-gap: keys derived from a seed and imported
# Then: public keys from the slot certificates, sealed PIN, agent unlock, a remote build over
# ssh-ng authenticated by 9A, a git commit signed by 9C and verified with allowed_signers, the
# pipeline user pushing to a cache and getting it signed by 9D through the root signer
# (verified by Determinate Nix), card sessions interleaving, a reboot, the card going away.
{
  pkgs,
  piv-vpicc,
  nix-piv,
  nix-piv-provision,
  nix-piv-seal-pin,
  determinate,
  mind-the-gap ? null,
  variant,
}:

let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;
  reader = "Virtual PCD 00 00";
  pin = "471120";
  cacheKey = "pavlov-card-1";
  principal = "pavlov-builder";
  hostKeys = import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs;
  seed = lib.concatStringsSep " " (lib.genList (_: "abandon") 23 ++ [ "art" ]);

  provision =
    if variant == "random" then
      "nix-piv-provision --reader '${reader}' --name ${principal} --pin ${pin} --puk 87654321 --yes"
    else
      "mind-the-gap -s '${seed}' -k pavlov-1 -n '${principal}' piv --curve p384"
      + " --pin-policy once --touch-policy never --management-key-touch never"
      + " upload -c 5437251 --pin ${pin} --yes";

  # a derivation nobody built yet, per tag; bash is an input, so it travels to the builder
  buildExpr = tag: ''derivation { name = "piv-${tag}"; system = "${system}"; builder = builtins.storePath "${pkgs.bash}/bin/bash"; args = [ "-c" "echo built-${tag} > $out" ]; }'';

  dnix = pkgs.writeShellScriptBin "dnix" ''
    exec ${determinate}/bin/nix --extra-experimental-features "nix-command cnsa" "$@"
  '';
in
{
  name = "nix-piv-builder-${variant}";

  nodes.builder = { ... }: {
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "no";
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        LogLevel = "VERBOSE";
      };
      hostKeys = [ { path = "/etc/ssh/ssh_host_ed25519_key"; type = "ed25519"; } ];
    };
    environment.etc."ssh/ssh_host_ed25519_key" = {
      source = hostKeys.snakeOilEd25519PrivateKey;
      mode = "0600";
    };
    users.users.ftl-build = {
      isNormalUser = true;
      home = "/home/ftl-build";
    };
    nix.settings = {
      trusted-users = [ "ftl-build" ];
      experimental-features = [ "nix-command" ];
    };
  };

  nodes.server = { config, ... }: {
    imports = [
      ../modules/virtual-card.nix
      ../modules/agent.nix
      ../modules/cache-signer.nix
    ];

    services.virtual-piv-card = {
      enable = true;
      package = piv-vpicc;
      persistent = true;
      version = "4.3.7";
    };

    users.users.ftl = {
      isSystemUser = true;
      group = "ftl";
      home = "/var/lib/ftl";
      createHome = true;
      shell = pkgs.bash;
    };
    users.groups.ftl = { };

    services.piv-agent = {
      enable = true;
      user = "ftl";
      nixDaemon = true;
    };
    services.piv-cache-signer = {
      enable = true;
      cacheDir = "/var/lib/ftl/cache";
      keyName = cacheKey;
      allowedUser = "ftl";
    };
    security.polkit.enable = true;

    environment.systemPackages = [
      nix-piv
      nix-piv-provision
      nix-piv-seal-pin
      dnix
      pkgs.git
      pkgs.openssh
    ] ++ lib.optional (mind-the-gap != null) mind-the-gap;

    nix.distributedBuilds = true;
    nix.buildMachines = [
      {
        hostName = "builder";
        sshUser = "ftl-build";
        protocol = "ssh-ng";
        inherit system;
        maxJobs = 2;
      }
    ];
    nix.settings = {
      max-jobs = 0;
      builders-use-substitutes = false;
      substituters = lib.mkForce [ ];
      experimental-features = [ "nix-command" ];
      allowed-users = [ "ftl" "root" ];
    };
    programs.ssh.knownHosts.builder = {
      hostNames = [ "builder" ];
      publicKey = hostKeys.snakeOilEd25519PublicKey;
    };
    environment.variables.NIX_PIV_READER = reader;
  };

  testScript = ''
    import shlex

    agent = "SSH_AUTH_SOCK=/run/piv-agent/agent.sock"

    def as_ftl(cmd):
        return f"su ftl -s ${pkgs.bash}/bin/bash -c {shlex.quote(cmd)}"

    def build(tag):
        expr = """${buildExpr "TAG"}""".replace("TAG", tag)
        return server.succeed(as_ftl(f"nix-build --no-out-link -E '{expr}'")).strip()

    def build_fails(tag):
        expr = """${buildExpr "TAG"}""".replace("TAG", tag)
        return server.fail(as_ftl(f"nix-build --no-out-link -E '{expr}' 2>&1"))

    start_all()
    builder.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")
    server.wait_until_succeeds("opensc-tool -n", timeout=120)

    with subtest("the card stands in for a YubiKey 4"):
        info = server.succeed("ykman --reader '${reader}' piv info")
        print(info)
        assert "PIV version:              4.3.7" in info, info
        server.fail("ykman --reader '${reader}' piv keys generate -a ED25519 -m 010203040506070801020304050607080102030405060708 9c - 2>&1")

    with subtest("provisioning (${variant})"):
        out = server.succeed("${provision} 2>&1")
        print(out[-3000:])
        info = server.succeed("ykman --reader '${reader}' piv info")
        print(info)
        assert "Management key algorithm: TDES" in info, info
        ${lib.optionalString (variant == "mtg") ''
        print(server.succeed("mind-the-gap -s '${seed}' -k pavlov-1 -n '${principal}' piv --curve p384 --pin-policy once --touch-policy never --management-key-touch never check -c 5437251 --pin ${pin} 2>&1"))
        ''}

    with subtest("nix-piv reads the keys from the slot certificates"):
        info = server.succeed("nix-piv info")
        print(info)
        for slot in ("9a", "9c", "9d"):
            assert f"slot {slot}:  ecdsa-p384" in info, info
        keys = server.succeed("nix-piv pubkeys --principal ${principal} --key-name ${cacheKey}")
        print(keys)
        lines = [line for line in keys.splitlines() if not line.startswith("#")]
        ssh_key, signing_key, allowed_signer, nix_key = lines
        assert ssh_key.startswith("ecdsa-sha2-nistp384 "), ssh_key
        assert signing_key.startswith("key::ecdsa-sha2-nistp384 "), signing_key
        assert nix_key.startswith("${cacheKey}:"), nix_key

    with subtest("the PIN is sealed and the agent unlocks itself"):
        server.succeed("printf ${pin} | nix-piv-seal-pin")
        server.fail(as_ftl("cat /var/lib/piv-agent/pin.cred"))
        server.succeed("systemctl restart piv-agent.service")
        server.wait_for_unit("piv-agent-unlock.service")
        listed = server.succeed(as_ftl(f"{agent} ssh-add -L"))
        print(listed)
        assert ssh_key.split()[1] in listed, listed
        fingerprint = server.succeed(
            f"echo '{ssh_key}' | ssh-keygen -lf - | cut -d' ' -f2"
        ).strip()

    with subtest("the builder trusts 9A; a remote build runs there"):
        builder.succeed("install -d -m 700 -o ftl-build /home/ftl-build/.ssh")
        builder.succeed(f"echo '{ssh_key}' > /home/ftl-build/.ssh/authorized_keys")
        builder.succeed("chown ftl-build /home/ftl-build/.ssh/authorized_keys")
        server.succeed(as_ftl(f"{agent} ssh -o BatchMode=yes ftl-build@builder true"))
        out = build("first")
        builder.succeed(f"test -e {out}")
        sshd_log = builder.succeed("journalctl -u sshd --no-pager")
        assert "Accepted publickey for ftl-build" in sshd_log and fingerprint in sshd_log, sshd_log[-2000:]

    with subtest("9C signs a git commit; allowed_signers verifies it"):
        server.succeed(as_ftl(
            "set -e; rm -rf /var/lib/ftl/repo; git init -q /var/lib/ftl/repo; cd /var/lib/ftl/repo;"
            " git config user.name pipeline; git config user.email ftl@pavlov;"
            " git config gpg.format ssh;"
            f" git config user.signingkey '{signing_key}';"
            f" echo bump > flake.lock; git add flake.lock; {agent} git commit -q -S -m 'lock bump'"
        ))
        server.succeed(f"echo '{allowed_signer}' > /tmp/allowed_signers")
        print(server.succeed(
            "cd /var/lib/ftl/repo && git -c safe.directory=/var/lib/ftl/repo -c gpg.ssh.allowedSignersFile=/tmp/allowed_signers verify-commit HEAD 2>&1"
        ))

    with subtest("the pipeline user pushes to the cache, the root signer signs it with 9D"):
        p1 = build("cache-a")
        p2 = build("cache-b")
        server.succeed(as_ftl(f"mkdir -p /var/lib/ftl/cache && nix copy --to file:///var/lib/ftl/cache {p1} {p2}"))
        server.succeed(as_ftl(f"printf '%s\\n' {p1} {p2} > /var/lib/ftl/queue"))
        unit = server.succeed("systemd-escape --path /var/lib/ftl/queue").strip()
        server.succeed(as_ftl(f"systemctl start --wait piv-cache-sign@{unit}.service"))
        sigs = server.succeed("grep -h '^Sig: ${cacheKey}:' /var/lib/ftl/cache/*.narinfo")
        print(sigs)
        assert len(sigs.splitlines()) == 2, sigs
        server.succeed(f"dnix store verify --store file:///var/lib/ftl/cache --trusted-public-keys '{nix_key}' {p1} {p2}")
        server.fail(f"nix store verify --store file:///var/lib/ftl/cache --trusted-public-keys '{nix_key}' {p1} 2>&1")
        # only the signer's own units: the pipeline user may not start anything else
        server.fail(as_ftl("systemctl start piv-agent-unlock.service 2>&1"))

    with subtest("card sessions interleave: the agent still signs after the cache signer"):
        server.succeed(as_ftl(f"{agent} ssh -o BatchMode=yes ftl-build@builder true"))
        out = build("after-signing")
        builder.succeed(f"test -e {out}")

    with subtest("after a reboot the agent unlocks itself and builds resume"):
        server.shutdown()
        server.start()
        server.wait_for_unit("multi-user.target")
        server.wait_for_unit("piv-agent-unlock.service")
        out = build("after-reboot")
        builder.succeed(f"test -e {out}")

    with subtest("with the card gone nothing builds; back in, it works again"):
        server.succeed("systemctl stop piv-vpicc.service")
        print(build_fails("card-gone")[-1500:])
        server.succeed("systemctl start piv-vpicc.service")
        server.wait_until_succeeds("opensc-tool -n", timeout=60)
        server.succeed("systemctl restart piv-agent.service")
        server.wait_for_unit("piv-agent-unlock.service")
        out = build("card-back")
        builder.succeed(f"test -e {out}")
  '';
}
