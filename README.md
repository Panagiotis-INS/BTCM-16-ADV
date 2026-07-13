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

## Notes
- The `community.windows` Ansible collection is required for the `win_unzip` module.
- The `chocolatey.chocolatey` collection (v1.5.1) is required for Chocolatey-based installs.
