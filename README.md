# Active Directory Security Audit

`Invoke-ADSecurityAudit.ps1` is a **read-only** PowerShell script that performs a
comprehensive inventory and security assessment of an Active Directory
forest/domain and produces a single, self-contained **HTML report**.

It is designed for two complementary goals:

1. **Cybersecurity assessment** – surface misconfigurations, weak settings,
   privileged accounts, Kerberos/delegation abuse paths, stale objects and other
   attack surface, summarised as severity-ranked findings.
2. **Disaster recovery / rebuild** – capture enough configuration detail
   (topology, policies, OU structure, GPO links, trusts, DNS, schema, etc.) to be
   able to recreate the directory.

> The script **never modifies** Active Directory. Every collection step is a query.

## Requirements

| Component | Required | Used for |
|-----------|----------|----------|
| RSAT **ActiveDirectory** module | Yes | Core directory data |
| RSAT **GroupPolicy** module | Optional | GPOs, GPO links, full GPO report |
| RSAT **DnsServer** module | Optional | DNS zones (needs `-Server`) |
| RSAT **ADCSAdministration** | Optional | Certificate Services awareness |

Run from a domain-joined machine in an **elevated** PowerShell session, ideally as
a member of *Domain Admins* or with delegated read rights. Best results when run
against a Domain Controller.

## Usage

```powershell
# Basic run, report written to the current folder
.\Invoke-ADSecurityAudit.ps1

# Full run: choose output folder, also export every dataset to CSV, verbose
.\Invoke-ADSecurityAudit.ps1 -OutputPath C:\Audit -ExportCsv -Verbose

# Target a specific DC, use alternate credentials, include full GPO settings
.\Invoke-ADSecurityAudit.ps1 -Server dc01.corp.local -Credential (Get-Credential) -IncludeGPOReport
```

If script execution is blocked, run PowerShell with:
`powershell -ExecutionPolicy Bypass -File .\Invoke-ADSecurityAudit.ps1`

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputPath` | current dir | Folder for the HTML/CSV output |
| `-Server` | nearest DC | Specific domain controller to query |
| `-Credential` | current user | Alternate credentials for all queries |
| `-InactiveDays` | `90` | Threshold for "stale" accounts/computers |
| `-ExportCsv` | off | Also export every dataset to CSV |
| `-IncludeGPOReport` | off | Generate the full native GPO settings HTML |

## What the report contains

1. Forest information (functional level, forest-wide FSMO, schema version)
2. Domain information (SID, functional level, containers, domain FSMO)
3. Recovery & retention (tombstone lifetime, AD Recycle Bin)
4. Domain controllers (OS, site, GC/RODC, roles)
5. Trusts (direction, type, SID filtering, selective auth)
6. Sites, subnets, site links & replication failures
7. Default password/lockout policy + fine-grained policies (PSO)
8. Users – full inventory with security attributes (SPN, pre-auth, delegation,
   password flags, SID history) and a posture summary
9. KRBTGT account age (Golden Ticket persistence indicator)
10. Privileged group membership (recursive)
11. Groups inventory
12. Computers (OS breakdown, stale, delegation, LAPS presence)
13. Kerberos delegation (unconstrained / constrained / RBCD)
14. Organizational Units (hierarchy, GPO link counts, deletion protection)
15. Group Policy objects, GPO links, optional full settings report
16. AdminSDHolder-protected objects (`adminCount=1`)
17. DNS zones (with `-Server` and DnsServer module)
18. Active Directory Certificate Services – CAs **plus heuristic ESC1/ESC2/ESC3
    template analysis**
19. Service accounts (SPN accounts + gMSA/sMSA)
20. LAPS coverage
21. Additional hardening – `ms-DS-MachineAccountQuota`, Pre-Windows 2000
    Compatible Access membership, Protected Users coverage for admins
22. **ACL analysis (attack paths)** – non-default principals with dangerous
    rights (GenericAll/WriteDacl/WriteOwner/…) or **DCSync** rights over the
    domain root, AdminSDHolder, privileged groups and admin accounts
23. **SYSVOL / GPP credentials** – scans Group Policy Preferences XML for
    `cpassword` and decrypts it (publicly known key)

### Usability features

- Every data table is **searchable** (per-table filter box) and **sortable**
  (click any column header).
- Boolean risk columns are colour-coded only where a `True`/`False` is actually
  security-relevant (no more "everything is red").
- CSV exports are protected against spreadsheet **formula injection**.

> **Heuristic note:** the ESC (AD CS) and ACL attack-path sections are
> heuristics meant to point you at likely issues. Confirm findings with
> dedicated tools (Certify/Certipy, BloodHound/SharpHound) before remediation.

The **Executive Summary** at the top lists all findings ranked
Critical → High → Medium → Low → Info, with severity counters.

## Output files

- `AD_Security_Audit_<timestamp>.html` – the main report
- `AD_GPO_FullReport_<timestamp>.html` – full GPO settings (with `-IncludeGPOReport`)
- `AD_Audit_CSV_<timestamp>\*.csv` – per-dataset CSVs (with `-ExportCsv`)

## Security note

The report contains sensitive directory configuration. **Treat it as
confidential**, store it securely, and delete copies when no longer needed.
