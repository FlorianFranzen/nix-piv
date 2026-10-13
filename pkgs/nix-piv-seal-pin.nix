# Seal the card PIN as a systemd credential for the piv-agent unlock and the cache signer.
{ writeShellApplication, systemd }:

writeShellApplication {
  name = "nix-piv-seal-pin";
  runtimeInputs = [ systemd ];
  text = ''
    # usage: nix-piv-seal-pin [OUTPUT]   (default /var/lib/piv-agent/pin.cred)
    # Reads the PIN from stdin when it is not a terminal, else asks for it. Encrypted with
    # --with-key=auto: the TPM 2.0 and the host key when there is a TPM, the host key alone
    # otherwise; decrypting needs the same machine.
    out="''${1:-/var/lib/piv-agent/pin.cred}"
    mkdir -p "$(dirname "$out")"
    if [ -t 0 ]; then
      systemd-ask-password --no-tty "Card PIN:" | systemd-creds encrypt --with-key=auto --name=piv-pin - "$out"
    else
      systemd-creds encrypt --with-key=auto --name=piv-pin - "$out"
    fi
    chmod 0600 "$out"
    echo "sealed the PIN to $out"
  '';
}
