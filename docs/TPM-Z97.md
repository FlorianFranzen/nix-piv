# A TPM 2.0 for pavlov (Gigabyte GA-Z97P-D3)?

*Research note, 2026-10-12. Question: if a Gigabyte GC-TPM2.0 goes onto the board's TPM
header, can `systemd-creds` seal the card PIN to it?*

## Short answer

**No. The GA-Z97P-D3 has no TPM header**, so there is nothing to plug a GC-TPM2.0 into.
Gigabyte's only manual for the model (Rev. 1001, April 2014, `mb_manual_ga-z97p-d3_e.pdf`,
the one linked from both the rev. 1.0 and rev. 1.1 support pages) lists 14 internal connectors:
ATX_12V_2X4, ATX, CPU_FAN, SYS_FAN1-3, SATA3 0-5, F_PANEL, F_AUDIO, SPDIF_O, F_USB30,
F_USB1/2/3, COMB, LPT, BAT, CLR_CMOS. The bottom edge, where Gigabyte puts the TPM header on
boards that have one, carries SPDIF_O, COMB, LPT, F_USB3, F_PANEL, F_USB2, F_USB1, and no TPM.

An earlier version of this note said the board had a header. That came from a search snippet
that was really about other Z97 boards (Z97X-Gaming 3, Z97X-UD5H, Z97-D3H have one); the manual
says otherwise. The rest of this note is still accurate for those boards and for any machine
whose TPM header lacks firmware support, so it is kept below.

For pavlov that leaves the host-key sealing that is already in place (`--with-key=auto` picks
it), or replacing the board. Any Intel 100-series or newer board has a firmware TPM (PTT) that
only needs switching on in the UEFI setup.

## The board

- **Header: no** (see above). Do look at the board for an unpopulated, unlabeled 2x10 footprint
  near the bottom edge, but the manual shows none for either revision.
- **Built-in TPM: no.** Intel's firmware TPM (PTT) reached desktop chipsets with the 100 series.
  pavlov reports `systemd-analyze has-tpm2` → `partial -firmware -driver`, which matches.
- **BIOS: F8 is the last release** (October 2015, rev. 1.0 and 1.1). No TPM support at all.

## For boards that do have a header: why the firmware is the problem

Gigabyte's retail Z97 BIOSes only drive TPM 1.2 modules. With a GC-TPM2.0 installed, Z97X-UD5H
owners saw the TPM page in the BIOS but "Current Status: Support Turned Off". Gigabyte eSupport
later sent some of them beta builds with TPM 2.0 (`Z97XUD5H.F11dTMP2.0`, an `F9d` for the
Z97M-D3H). Nothing comparable is known for the Z97P-D3; asking eSupport for one is worth a ticket
but cannot be planned on.

The module itself is fine: the GC-TPM2.0 carries an Infineon SLB9665, a TPM 2.0 chip. Infineon's
`TPMFactoryUpd` can even switch an SLB9665 between 1.2 and 2.0 firmware, so a 1.2-only module is
also not a dead end. That tool runs under Windows or an EFI shell, not Linux.

## Why Linux might not need the firmware

Three pieces line up:

1. **The bus decodes it anyway.** On Intel 9-series chipsets the TPM window
   `0xFED40000–0xFED47FFF` is always decoded to LPC (or SPI, by strap); the BIOS does not have to
   switch it on (9 Series PCH datasheet, memory map).
2. **The kernel can find and start it.** `tpm_tis.force=1` makes the driver register a device at
   `0xFED40000` without any ACPI entry (`drivers/char/tpm/tpm_tis.c`). The TIS driver has
   `TPM_OPS_AUTO_STARTUP`, and `tpm2_auto_startup()` answers a `TPM2_RC_INITIALIZE` with its own
   `TPM2_Startup(CLEAR)` ("Normally the firmware should start the TPM. This function is provided
   as a workaround if this does not happen", `drivers/char/tpm/tpm2-cmd.c`). It logs
   `starting up the TPM manually`.
3. **systemd does not insist on firmware support for credentials.** `systemd-creds encrypt`
   with the default `--with-key=auto` uses the TPM when `tpm2_is_mostly_supported()` holds,
   which is every support flag *except* `TPM2_SUPPORT_FIRMWARE`
   (`src/shared/creds-util.c`, `src/shared/tpm2-util.h`, systemd 261). Without firmware it only
   skips the PCR 11 signed-policy part, which needs UKI measurements anyway. The default PCR list
   is empty, so the credential is bound to the chip, not to boot measurements, which is all this
   setup needs. `auto` then means **host key and TPM**: decrypting needs both
   `/var/lib/systemd/credential.secret` and that physical chip.

What does not work without firmware support: measured boot (no PCR 0–7 values, no event log),
`systemd-cryptenroll` policies on those PCRs, and anything that waits on `tpm2.target` via
`systemd-tpm2-generator` (it looks at the ACPI table). `has-tpm2` will keep printing `-firmware`.

Risks: the module may sit in a state the firmware was supposed to handle (for example
physical-presence or an owner set by a previous machine); `tpm2_clear` from Linux needs the
platform hierarchy, which is normally the firmware's. A new module avoids most of that.

## Try-it checklist (for a board with a TPM header)

1. Buy a 20-1 pin LPC TPM 2.0 module (Gigabyte GC-TPM2.0, or a clone with an SLB9665 sold "for
   Gigabyte 20-1"). Mind the keyed pin when plugging it in, with the machine off.
2. In the BIOS, look for a TPM page. If one shows the module as TPM 2.0, use it and ignore step 3.
   If it says 1.2 only or "Support Turned Off", leave it disabled.
3. NixOS, for the kernel to probe and start the module itself:

   ```nix
   boot.kernelParams = [ "tpm_tis.force=1" "tpm_tis.interrupts=0" ];
   boot.initrd.availableKernelModules = [ "tpm_tis" ];
   ```
4. After a reboot, check:

   ```sh
   journalctl -k -b | grep -i tpm          # "tpm_tis tpm_tis: 2.0 TPM (device-id 0x1B, rev-id 22)", "starting up the TPM manually"
   ls -l /dev/tpm0 /dev/tpmrm0
   cat /sys/class/tpm/tpm0/tpm_version_major   # 2
   systemd-analyze has-tpm2                # expected: partial, -firmware, but +driver +system +subsystem +libraries
   nix shell nixpkgs#tpm2-tools -c tpm2_getcap properties-fixed | grep -A2 MANUFACTURER   # IFX
   ```
5. Prove the TPM is usable for credentials, then re-seal the card PIN with it:

   ```sh
   echo test | systemd-creds encrypt --with-key=tpm2 - - >/dev/null && echo "TPM sealing works"   # fails today
   systemd-ask-password "Card PIN:" | systemd-creds encrypt --with-key=auto --name=card-pin - /var/lib/card-ssh/pin.cred
   systemctl restart card-ssh-unlock && ssh-add -l     # SSH_AUTH_SOCK=/run/card-ssh-agent/agent.sock
   ```

   With the module present, `auto` now means host key **and** TPM; the same NixOS config keeps
   working, only the credential file changes.
6. If step 4 shows nothing: no LPC decode problem is expected on this chipset, so the likely
   causes are a 1.2-firmware module (check the vendor), a seating problem, or a module that needs
   firmware init the kernel does not do. Gigabyte eSupport (TPM 2.0 beta BIOS for GA-Z97P-D3)
   is the remaining route.

## Sources

- [GA-Z97P-D3 manual, Rev. 1001](https://download1.gigabyte.com/Files/Manual/mb_manual_ga-z97p-d3_e.pdf)
  (layout on page 4, internal connectors on page 12: no TPM header) and
  [BIOS downloads, F7/F8](https://www.gigabyte.com/Motherboard/GA-Z97P-D3-rev-11/support)
- [Win-Raid: Z97X-UD5H with TPM 2.0](https://winraid.level1techs.com/t/request-gigabyte-z97x-ud5h-with-tpm-2-0-support/37819)
  (stock BIOS "Support Turned Off", eSupport beta `F11dTMP2.0`)
- [Win-Raid: SLB9665 firmware](https://winraid.level1techs.com/t/latest-firmware-for-tpm2-0-infineon-slb-9665/111327)
  (1.2 ↔ 2.0 with TPMFactoryUpd)
- [Intel 9 Series PCH datasheet](https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/9-series-chipset-pch-datasheet.pdf)
  (FED4_0000h–FED4_7FFFh decoded to LPC/SPI for the TPM)
- Linux `drivers/char/tpm/tpm_tis.c` (force), `tpm_tis_core.c` (`TPM_OPS_AUTO_STARTUP`),
  `tpm2-cmd.c` (`tpm2_auto_startup`, `tpm2_startup`)
- systemd 261 `src/shared/creds-util.c`, `src/shared/tpm2-util.h`
  (`tpm2_is_mostly_supported` excludes the firmware flag), `systemd-creds(1)` (`--with-key=auto`,
  empty default `--tpm2-pcrs`)
- [systemd PR 32314](https://github.com/systemd/systemd/pull/32314) (detection relies on the ACPI
  table for `has-tpm2` / the generator; closed)
