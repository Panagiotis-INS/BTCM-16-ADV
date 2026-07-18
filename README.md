# BTCMP-16 — Digital Forensics Lab Environment - Windows
applied to BTCMP-16- Memory Forensics Evidence Gathering
## Overview

This lab environment is built around **Digital Forensics** scenarios.

---

## Topology

| Host | Role | Network | CIDR | IP |
|------|------|---------|------|----|
| axvm | Analyst Workstation (Xubuntu Noble) | access-switch | 10.10.10.0/24 | 10.10.10.3 |
| wvvm | Victim/Evidence Machine (Windows Server 2019) | access-switch | 10.10.10.0/24 | 10.10.10.4 |
| router | Network Router (Debian 12) | access-switch | 10.10.10.0/24 | 10.10.10.1 |

---

## Machines

### AXVM — Analyst Workstation (Xubuntu Noble)
User `attacker` / `Password123!` (sudoer, SSH enabled).

**Software (via apt):**
- git
- autopsy
- sleuthkit
- volatility3
- foremost
- binutils (provides `strings`)
- cifs-utils, smbclient (for mounting `\\wvvm\investigation`)
- terminator

**Sliver C2:**
- Server installed via the official BishopFox/sliver GitHub install script (`https://sliver.sh/install`).
- Client (`sliver`) binary pulled from the latest BishopFox/sliver GitHub release into `/usr/local/bin/`.
- Server runs as a systemd unit (`sliver.service`), enabled on boot.

**Notes:**
- Mount point `/mnt/investigation` is created for mounting the wvvm SMB share.

---

### WVVM — Victim / Evidence Machine (Windows Server 2019)
User `LocalAdmin` / `Password123!` (admin, RDP enabled).

**Hardening disabled (lab target):**
- Windows Defender real-time monitoring, behavior monitoring, IOAV, script scanning, and MAPS reporting disabled via policy registry keys and `Set-MpPreference`.
- `Windows-Defender` server feature uninstalled (reboot on first provision if required).

**Software:**
- DumpIt (memory acquisition; extracted to `C:\Tools\DumpIt`, Desktop shortcut on public Desktop).
- Sysinternals Strings (extracted to `C:\Tools\Strings`).
- SMB share `\\wvvm\investigation` → `C:\Investigation` (Everyone read/write, share + NTFS).

---

## Purple Team Scenario — FIN7 TTP Emulation

Students emulate FIN7 tradecraft from `axvm` (Sliver C2) against `wvvm`, then pivot to the analyst role and recover flags from live-system / memory / disk forensics. IOCs are pre-planted by the provisioner so the lab is deterministic.

| # | MITRE | TTP | Artifact / Detection Path | Flag |
|---|-------|-----|---------------------------|------|
| 1 | — | Initial foothold | `C:\Users\LocalAdmin\Desktop\initial_foothold_flag.txt` (read via Sliver beacon) | `CTF{1n1t14l_F00th0ld_0n_wvvm}` |
| 2 | T1547.001 | Registry Run Key persistence | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — flag is the value name | `CTF{P3r5i5t3nc3_v14_Run_K3y5}` |
| 3 | T1053.005 | Scheduled Task persistence | Task `GoogleUpdaterCore` (`C:\Windows\System32\Tasks\GoogleUpdaterCore` XML) — flag in description | `CTF{Sch3dul3d_T4sk_P3rs1st3nc3}` |
| 4 | T1546.003 | WMI Event Subscription (Carbanak signature) | `root\subscription` → `CommandLineEventConsumer` name; extract via `Get-WmiObject -Namespace root\subscription -Class __EventConsumer` or `OBJECTS.DATA` parsing | `CTF{WMI_3v3nt_Subscr1pt10n_C4rb4n4k}` |
| 5 | T1548.002 | UAC Bypass via fodhelper | `HKCU:\Software\Classes\ms-settings\Shell\Open\command` — flag in `(Default)` value | `CTF{UAC_Byp4ss_v14_f0dh3lp3r}` |
| 6 | T1070.006 | Timestomping | `C:\ProgramData\svc\svcupdater.exe` — MFT `$STANDARD_INFO` vs `$FILE_NAME` mismatch (sleuthkit `istat`/`fls`); flag inside file (`strings`) | `CTF{T1m3st0mp3d_MFT_M1sm4tch}` |
| 7 | T1564.004 | Alternate Data Streams | `C:\Investigation\notes.txt:hidden` — enumerate with `dir /r` or Sysinternals `streams.exe` | `CTF{H1dd3n_1n_Alt3rn4t3_D4t4_Str34m}` |
| 8 | T1074.001 | Local staging (decoy inside archive) | `C:\ProgramData\svc\stage.7z` → `_stage_decoy.txt` (recover via foremost carving on disk image / after password) | `CTF{Ex71ltr4t10n_St4g3d_H3r3}` |
| 9 | T1560.001 | Password-protected archive (`-mhe=on`) | Password required to list/extract `stage.7z` — hunt in memory / Sliver session logs | `CTF{P4ssw0rd_Pr0t3ct3d_4rch1v3}` |
| 10 | T1082 / T1087 | Discovery via Seatbelt/SharpHound | `C:\Windows\Prefetch\SEATBELT.EXE-*.pf` → dropper folder `C:\ProgramData\svc\seatbelt_out.txt` | `CTF{S34tb3lt_Pr3f3tch_D1sc0v3ry}` |
| 11 | T1489 | Service Stop (impact) | `Spooler` service stopped + disabled; correlate via events 7036 / 7040 | *(detection-only, no flag)* |
| 12 | T1070.001 | Event Log Clearing | Event ID **1102** as first entry in fresh Security log; corroborating artifact `C:\Users\Public\log_cleared_by.txt` | `CTF{Cl34r3d_S3cur1ty_L0g}` |

**Tool-to-TTP mapping (on axvm):**
- `sliver` — C2 beacon, staging, service stop, command execution, prefetch generation.
- `volatility3` — WMI subscription objects, running processes, hashdump for credential IOCs.
- `sleuthkit` / `autopsy` — MFT timestamp mismatch, ADS enumeration, deleted file recovery.
- `foremost` — carve `stage.7z` from unallocated space.
- `binutils` (`strings`) — read flag content in timestomped/staged binaries.
- `smbclient` / `cifs-utils` — mount `\\wvvm\investigation` to pull evidence.

---

## Notes
- The `community.windows` Ansible collection is required for the `win_unzip` module.
- The `chocolatey.chocolatey` collection (v1.5.1) is required for Chocolatey-based installs (used for 7-Zip on `wvvm`).
