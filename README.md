# NXC Generator & Initial Access Toolkit

Two tools for Active Directory penetration testing and red team engagements.

---

## Tools

### `adblood` — AD Initial Access & Enumeration
Interactive script for initial Active Directory reconnaissance — automates BloodHound collection, user/group enumeration, credential attacks, and domain mapping from a foothold.

### `nxcgen` — NetExec One-Liner Generator
Generates 130+ customized NetExec commands for your target environment — from recon through domain compromise. Outputs a colorful, organized reference file you can use throughout the engagement.

---

## Install

```bash
# adblood — AD Initial Access
curl -sSL https://raw.githubusercontent.com/xl337x/NXC_Generator-And-Initial-Access/main/AD_intial.sh -o /usr/local/bin/adblood && chmod +x /usr/local/bin/adblood
```

```bash
# nxcgen — NetExec Command Generator
curl -sSL https://raw.githubusercontent.com/xl337x/NXC_Generator-And-Initial-Access/main/nxc-gen.sh -o /usr/local/bin/nxcgen && chmod +x /usr/local/bin/nxcgen
```

> Run with `sudo` if `/usr/local/bin` requires root.

## Usage

```bash
adblood        # Launch AD initial access wizard
nxcgen         # Launch NXC command generator
```

## Requirements

- Kali Linux / Parrot OS (or any Debian-based with pentest tools)
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec)
- [Impacket](https://github.com/fortra/impacket)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) (optional)
