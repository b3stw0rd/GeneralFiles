# Wutai — Internal Penetration Test Report

**Engagement:** VulnLab — Wutai (Active Directory Multi-Forest)
**Report date:** 2026-05-22
**Tester:** cezary.pasierkiewicz@gmail.com
**Assessment window:** 2026-03-29 → 2026-05-21

---

## 1. Executive Summary

A black-box internal penetration test was performed against the `junon.vl` forest, starting from an external pivot at `10.10.110.0/24` and ending with full control over both AD domains in scope: the child domain `WORK.JUNON.VL` and the parent domain `EU.JUNON.VL`.

The path to forest compromise required no zero-day exploitation. Five compounding weaknesses were sufficient:

1. **Weak, shared seasonal password** (`Summer2023`) accepted by four users in `WORK.JUNON.VL`.
2. **Sensitive credentials in a writable SMB share** (`deployment$` on `S021M015`) protecting a service account password with a trivially reversible custom binary (`SecurePass.exe`).
3. **Service account `svc_me` was local admin on `S021M015`**, enabling SAM/LSA extraction and recovery of DCC2/LSA secrets, including `_SC_PDQDeploy` plaintext.
4. **Domain credentials cached on a workstation** (`S021W105`) recoverable by an attacker with local admin via reused LSA secrets.
5. **Cross-forest trust abused via inter-realm TGT** (`krbtgt_EU.JUNON.VL@WORK.JUNON.VL`) to pivot from child DA → parent DA.

Additionally, **AD CS misconfigurations** were identified on the parent CA `eu-S021M200-CA`: **ESC7** (dangerous principal permissions) and **ESC8** (web enrollment over HTTP), plus broad **ESC4** template ownership and **ESC1/ESC2/ESC3/ESC15** on `SubCA`/`WebServer` templates.

**Outcome:** 5 flags captured, full DCSync of `WORK.JUNON.VL`, foothold on parent `EU.JUNON.VL` via forged inter-realm ticket and impersonation of `Administrator` to services on `s021m215.eu.junon.vl`.

---

## 2. Scope

| Item | Detail |
|------|--------|
| External pivot range | `10.10.110.0/24` (4 hosts up) |
| Internal target range | `172.16.21.0/24` |
| In-scope domains | `work.junon.vl` (child), `eu.junon.vl` (parent), `junon.vl` (forest root) |
| Out-of-scope | Denial-of-service, social engineering against real users, persistence beyond engagement window |

### 2.1 External-facing hosts (nmap top-1000 TCP)

| IP | Open ports | Note |
|----|------------|------|
| 10.10.110.3 | 22/ssh, 8080/http-proxy | Likely jump/proxy |
| 10.10.110.15 | 22/ssh, 8443/https-alt | SIEM viewer (`viewer:eeDB364ed41#.`) — “to watch for alerts” |
| 10.10.110.100 | 22/ssh, 443/https | Pivot |

### 2.2 Internal targets discovered

| IP | Hostname | OS | Domain | Notes |
|----|----------|----|---------|-------|
| 172.16.21.10  | S021M005 | Server 2022 (20348) | work.junon.vl | DC; SMB signing ON |
| 172.16.21.140 | S021W105 | Win10 / Server 2019 (19041) | work.junon.vl | Workstation; signing OFF |
| 172.16.21.180 | S021M010 | Server 2022 (20348) | work.junon.vl | Server; signing OFF; Null Auth |
| 172.16.21.195 | S021M015 | Server 2022 (20348) | work.junon.vl | File / WSUS / SecurePass host |
| 172.16.21.222 | S021M200 | Server 2022 (20348) | eu.junon.vl | EU DC + ADCS (`eu-S021M200-CA`) |

---

## 3. Attack Narrative

### Stage 1 — Foothold via password spray
A user list was harvested from the DC (`work.junon.vl`) over SMB null/guest enumeration and sprayed against SMB with the candidate password `Summer2023`. Four accounts succeeded:

```
work.junon.vl\Wendy.Vincent     : Summer2023
work.junon.vl\Melanie.Mueller   : Summer2023
work.junon.vl\Terry.Lowe        : Summer2023
work.junon.vl\Hazel.Simpson     : Summer2023
```

The same password failed against the EU domain (`eu.junon.vl\Melanie.Mueller` → `STATUS_LOGON_FAILURE`), confirming the spray was successful only on `work.junon.vl`.

### Stage 2 — Loot from writable SMB share
`Melanie.Mueller` had read/write on multiple shares of `S021M015` (`deployment$`, `finance$`, `homes`, `install$`, `it`, `transfer`). On `deployment$`:

- `config.xml` referenced an encrypted password for **`svc_me`** stored in a custom binary `SecurePass.exe` (also found in `install$`).
- A user flag was captured from `homes/Amy.Ball/flag.txt` → `WUTAI{4b615fe8a5b0d36f581ff1f78a708821}`.

```xml
<securepass>
    <username>svc_me</password>
    <password>SP81274145f4a5857b839ee7b500f1d66e8a044d12211781b515e7bae67bb7abce</password>
</securepass>
```

The `SecurePass.exe` decryption routine was patched (`SecurePass_patched.exe`) to print the recovered plaintext:

```
work.junon.vl\svc_me : jYEp9bq32KFLVL!
```

### Stage 3 — Local admin on S021M015 → SAM/LSA/NTDS extraction
`svc_me` is local admin on `172.16.21.195` (`Pwn3d!` confirmed by NetExec). Local SAM, LSA secrets and cached domain credentials were extracted:

- Local Administrator NT hash: `cb43b835eaa78aeb5e55760a04227fd1`
- DCC2 hashes recovered for: `Amy.Ball`, `Administrator`, `svc_deploy`, `svc_me`
- LSA secret `_SC_PDQDeploy` → plaintext **`AssetManagement2024!`** (PDQ Deploy service account password)
- `$MACHINE.ACC` machine hash recovered.

Admin flag from this host: `WUTAI{f488998985a51efb94a2a8f859e5e7c2}`.

### Stage 4 — Lateral to S021W105 and additional cached creds
Using the credentials above (likely via SMB remote service / `secretsdump.py`), `172.16.21.140` (`S021W105`) was compromised:

- Local Administrator NT hash: `776780089d24a778e3db6aa2ef96a5b4`
- DCC2 hashes for `Administrator`, `Carly.Adams`, `svc_deploy`
- LSA `DefaultPassword` (autologon): **`ZMskoMXML_qC17`**

Admin flag: `WUTAI{7a7ae1d7a346eb89e3553a8ebc645b96}`.

### Stage 5 — Domain compromise (WORK.JUNON.VL)
With `svc_deploy` recovered (cached on multiple hosts; reused) and PDQ Deploy / Asset-Management privileges, NTDS replication (DCSync) succeeded against the work-domain DC `S021M005` (172.16.21.10):

- `Administrator:500: … :b976dde1bcbbf31cbdab60d2a5a5449d`
- `krbtgt:502: … :bc6cfd11862244676f00002ed3ba71b8`
- Full domain NT hashes (1300+ accounts) including `svc_me`, `svc_ldap`, `svc_deploy`, `vdi_user`.
- Kerberos AES256 keys for `Administrator`, `krbtgt`, all service accounts.

Admin flags: 
- 172.16.21.10  → `WUTAI{b9d501b890863e28f125912b89de0c7e}`
- 172.16.21.180 → `WUTAI{738add38d1f3dd4c4af8e7c9b1f7c98a}`

### Stage 6 — Cross-forest pivot (WORK → EU)
With the work-domain `krbtgt` key in hand and a writeable parent-side trust, an inter-realm Ticket Granting Ticket was forged for `EU.JUNON.VL`:

- `Administrator@krbtgt_EU.JUNON.VL@WORK.JUNON.VL.ccache`

The ticket was used to request service tickets in the parent domain and impersonate `Administrator` against `s021m215.eu.junon.vl` services:

- `Administrator@HTTP_s021m215.eu.junon.vl@EU.JUNON.VL.ccache`
- `Administrator@BackupSVC_s021M215.eu.junon.vl@EU.JUNON.VL.ccache`

### Stage 7 — AD CS exposure on EU domain
Certipy enumeration of the EU CA (`eu-S021M200-CA`, host `s021m200.eu.junon.vl`) returned the following findings (full output in `20260521054532_Certipy.txt` / `.json` and `20260521083009_Certipy.txt`):

- **CA-level**
  - `ESC7` — dangerous principal permissions on CA object
  - `ESC8` — Web Enrollment enabled over **HTTP** (NTLM relay → certificate as DA / DC)
- **Template-level**
  - `SubCA` template: `ESC1`, `ESC2`, `ESC3`, `ESC4`, `ESC15` (CVE-2024-49019 candidate if unpatched), Enrollee-supplies-subject + Client Authentication
  - `WebServer` template: `ESC4`, `ESC15`
  - `KerberosAuthentication`, `DomainControllerAuthentication`, `DomainController`, `Machine`, `Administrator`, `EFSRecovery`, `DirectoryEmailReplication`, and ~20 additional templates: `ESC4` (template owned by `Authenticated Users`-reachable principal)

Any one of ESC7 or ESC8 alone is sufficient to escalate to a Domain Admin / Domain Controller certificate in `EU.JUNON.VL`.

---

## 4. Findings & Risk Rating

| # | Finding | Affected asset(s) | Severity |
|---|---------|-------------------|----------|
| F-01 | Weak shared password `Summer2023` accepted by 4 domain users | `work.junon.vl` | **Critical** |
| F-02 | Writable SMB share `deployment$` exposes service-account credentials | `S021M015` (172.16.21.195) | **Critical** |
| F-03 | `SecurePass.exe` uses reversible, key-embedded cipher to “protect” passwords | All hosts using SecurePass | **High** |
| F-04 | Service account `svc_me` is local admin on a member server | `S021M015` | **High** |
| F-05 | LSA secrets contain plaintext PDQ Deploy password and autologon | `S021M015`, `S021W105` | **High** |
| F-06 | Reused/cached domain credentials enable lateral movement to additional hosts | Workstations / member servers | **High** |
| F-07 | Domain compromise via DCSync (NT hash + AES key for `krbtgt`) | `WORK.JUNON.VL` | **Critical** |
| F-08 | Forest trust abused via forged inter-realm TGT to pivot WORK → EU | `EU.JUNON.VL` | **Critical** |
| F-09 | ADCS — Web Enrollment over HTTP (ESC8) | `eu-S021M200-CA` | **Critical** |
| F-10 | ADCS — Dangerous CA permissions (ESC7) | `eu-S021M200-CA` | **High** |
| F-11 | ADCS — `SubCA` template allows ESC1/ESC2/ESC3/ESC15 | `eu-S021M200-CA` | **High** |
| F-12 | ADCS — Broad template ownership by a non-admin principal (ESC4) | `eu-S021M200-CA` | **Medium** |
| F-13 | SMB signing disabled on `S021M010`, `S021M015`, `S021W105` (NTLM relay surface) | Multiple | **Medium** |
| F-14 | Null/Guest SMB authentication allowed on `S021M005`, `S021M010`, `S021M200` | DCs / member server | **Medium** |
| F-15 | GPP-style proxy registry settings disclosed in SYSVOL (IT_PROXY / REMOTE_PROXY) | `SYSVOL` | **Low** |
| F-16 | Internal proxy/SIEM viewer creds in cleartext (`viewer:eeDB364ed41#.` at 10.10.110.15) | Edge bastion | **Medium** |

---

## 5. Captured Flags (5)

| Host / context | Flag |
|----------------|------|
| `homes\Amy.Ball\flag.txt` (S021M015 share, user flag) | `WUTAI{4b615fe8a5b0d36f581ff1f78a708821}` |
| 172.16.21.10 admin (`S021M005`, work DC) | `WUTAI{b9d501b890863e28f125912b89de0c7e}` |
| 172.16.21.140 admin (`S021W105`) | `WUTAI{7a7ae1d7a346eb89e3553a8ebc645b96}` |
| 172.16.21.180 admin (`S021M010`) | `WUTAI{738add38d1f3dd4c4af8e7c9b1f7c98a}` |
| 172.16.21.195 admin (`S021M015`) | `WUTAI{f488998985a51efb94a2a8f859e5e7c2}` |

---

## 6. Recovered Credentials (summary, sensitive)

| Account | Type | Value / hash |
|---------|------|--------------|
| `work.junon.vl\Wendy.Vincent` | password | `Summer2023` |
| `work.junon.vl\Melanie.Mueller` | password | `Summer2023` |
| `work.junon.vl\Terry.Lowe` | password | `Summer2023` |
| `work.junon.vl\Hazel.Simpson` | password | `Summer2023` |
| `work.junon.vl\svc_me` | password | `jYEp9bq32KFLVL!` |
| `_SC_PDQDeploy` (LSA, S021M015) | password | `AssetManagement2024!` |
| `DefaultPassword` (LSA, S021W105) | password | `ZMskoMXML_qC17` |
| `S021M015 Administrator` | NT hash | `cb43b835eaa78aeb5e55760a04227fd1` |
| `S021W105 Administrator` | NT hash | `776780089d24a778e3db6aa2ef96a5b4` |
| `WORK\Administrator` | NT hash | `b976dde1bcbbf31cbdab60d2a5a5449d` |
| `WORK\krbtgt` | NT hash | `bc6cfd11862244676f00002ed3ba71b8` |
| `WORK\svc_me` | NT hash | `3329df192473673b02ba1ec715e2b764` |
| `WORK\svc_ldap` | NT hash | `359f4c987d6445da2dcf4ad629458c6b` |
| `WORK\svc_deploy` | NT hash | `661a4252f080128ffb93e415652df659` |
| `viewer` (10.10.110.15 SIEM) | password | `eeDB364ed41#.` |
| Inter-realm TGT `WORK→EU` | Kerberos ccache | `Administrator@krbtgt_EU.JUNON.VL@WORK.JUNON.VL.ccache` |
| `EU\Administrator` (impersonated, service ticket) | ccache | `HTTP/s021m215.eu.junon.vl`, `BackupSVC/s021M215.eu.junon.vl` |

Full NTDS dump (1300+ users, krbtgt, all svc_* accounts, AES keys) preserved in `secretsdump_work_full.txt`.

---

## 7. Recommendations

### 7.1 Immediate (within 7 days)
1. **Rotate `krbtgt` twice** in `WORK.JUNON.VL` and validate forest trust quarantine settings on `EU.JUNON.VL`.
2. **Reset all service accounts** disclosed above (`svc_me`, `svc_deploy`, `svc_ldap`, PDQ Deploy account) and **rotate the local administrator passwords** on every domain-joined host (deploy LAPS/Windows LAPS).
3. **Force a domain-wide password reset** with a policy that blocks seasonal/dictionary passwords (e.g. `Summer2023`, `Welcome1`, …). Enforce the “Banned password list” feature of AAD Password Protection on-prem.
4. **Disable AD CS Web Enrollment over HTTP** on `eu-S021M200-CA`, require **EPA** + HTTPS, and apply `RequireEKU=Smartcard Logon` or filter `SubjectAltName`.
5. **Remove ESC1/ESC2/ESC3 capabilities** from the `SubCA` template (it should be CA-signed only) and re-own all templates currently held by non-admin principals (ESC4).

### 7.2 Short term (within 30 days)
6. Remove `svc_me` from local Administrators on `S021M015`; switch deployment to a gMSA with constrained delegation if required.
7. Replace `SecurePass.exe` with a vault that uses DPAPI-NG bound to the machine identity, or a real secrets manager (CyberArk / HashiCorp Vault).
8. Audit and remove **writable** SMB shares (`deployment$`, `finance$`, `homes`, `install$`, `it`, `transfer` on `S021M015`) — enforce least privilege; remove world-writable defaults.
9. Enable **SMB signing required** on all member servers and workstations (currently disabled on `S021M010`, `S021M015`, `S021W105`).
10. Disable **null/anonymous SMB** access on `S021M005`, `S021M010`, `S021M200` (RestrictAnonymous = 2).

### 7.3 Strategic
11. Implement Tier-0 isolation: Tier-0 admins must not log on to Tier-1/Tier-2 systems (the presence of `WORK\Administrator` DCC2 hash on `S021M015` and `S021W105` is the textbook violation).
12. Move PDQ Deploy / asset-management agents to a dedicated, network-segmented privileged-access workstation model.
13. Enable Credential Guard and disable WDigest / cleartext credentials on all Server 2019+ hosts.
14. Review the forest trust between `WORK.JUNON.VL` and `EU.JUNON.VL`: enable **SID filtering / quarantine** so a compromised child cannot mint inter-realm tickets for the parent.

---

## 8. Evidence Index

All raw artefacts retained in `/home/kali/HTB/Wutai/`:

| Artefact | Description |
|----------|-------------|
| `tcp_common.nmap` / `.xml` / `.gnmap` | External nmap of `10.10.110.0/24` |
| `discovery_172_16_21.txt` | Internal host discovery (NetExec SMB) |
| `users.txt`, `users_wo_domain.txt`, `known_users.txt` | Harvested user lists |
| `password_spray_results.txt` | NetExec spray with `Summer2023` |
| `shares_melanie.txt` | SMB share enumeration as `Melanie.Mueller` |
| `spider/172.16.21.195.json` | Spidered file listing on S021M015 |
| `loot/M015/SecurePass.exe`, `SecurePass_patched.exe`, `config.xml`, `Amy.Ball/flag.txt` | SecurePass exfil + patched binary |
| `loot/SYSVOL/Groups.xml`, `IT_PROXY_Registry.xml`, `REMOTE_PROXY_Registry.xml` | GPP / SYSVOL artefacts |
| `loot/EU_SYSVOL/` | EU SYSVOL replicated tree |
| `dump_M015.txt`, `secretsdump_M015*.txt`, `secretsdump_offline.txt` | S021M015 SAM/LSA/DCC2 |
| `loot/sam.save`, `sec.save`, `sys.save` | Offline registry hives — S021M015 |
| `loot/W105_SAM.save`, `W105_SECURITY.save`, `W105_SYSTEM.save`, `secretsdump_W105*.txt` | S021W105 hives + dumps |
| `secretsdump_work_full.txt` | Full DCSync of `WORK.JUNON.VL` (NTDS) |
| `Administrator.ccache`, `Administrator@krbtgt_EU.JUNON.VL@WORK.JUNON.VL.ccache`, `Administrator@HTTP_s021m215.eu.junon.vl@EU.JUNON.VL.ccache`, `Administrator@BackupSVC_s021M215.eu.junon.vl@EU.JUNON.VL.ccache` | Kerberos tickets / inter-realm TGT |
| `20260521054532_Certipy.txt` / `.json` | Certipy enum (initial, EU CA) |
| `20260521075558_Certipy.txt` | Certipy re-enum |
| `20260521083009_Certipy.txt` / `.json` | Certipy final (full forest) |
| `bloodhound/`, `bloodhound_v2/` | BloodHound collections (JSON + zip) |
| `bloodhound_v2/loot/flags/` | Per-host admin flags |
| `rdp_test.txt`, `winrm_test.txt` | RDP / WinRM authentication probes |
| `internal_ips.txt`, `zakres.txt` | Target lists |

---

*End of report.*
