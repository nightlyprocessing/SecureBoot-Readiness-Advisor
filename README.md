# Secure Boot Readiness Advisor

A read-only PowerShell advisor for checking Windows Secure Boot readiness ahead of the 2026 Secure Boot certificate transition. Version 2.0.16 polishes report guidance by separating current BitLocker state from historical BitLocker/Secure Boot integrity events, softening Windows 10 ESU servicing-path wording, and improving event de-duplication.

This tool audits Secure Boot state, firmware mode, boot manager signature status, UEFI certificate text signals, Secure Boot registry indicators, TPM state, BitLocker recovery risk, recent relevant event logs, firmware age, hotfixes, and Windows support posture. It then produces deterministic recommendations in TXT, HTML, JSON, and CSV formats.

## Why this exists

The original Secure Boot certificates introduced around the Windows 8 / UEFI Secure Boot era are reaching the end of their planned lifecycle in 2026. Updated 2023-era certificates are being rolled out across supported systems through Windows servicing and OEM firmware paths. Older, unsupported, specialized, or poorly maintained systems may need closer attention.

This project is intended to help users and technicians answer a practical question:

> Where does this Windows device appear to stand, and what should I check before making firmware or Secure Boot changes?

## Safety posture

This script is intentionally **read-only**.

It does **not**:

- Enable or disable Secure Boot
- Modify UEFI variables
- Modify DB, DBX, KEK, or PK
- Suspend or resume BitLocker
- Change BCD
- Install Windows updates
- Install firmware updates
- Convert MBR to GPT
- Reboot the machine

The advisor recommends remediation steps, but it does not perform them.

## Quick start

Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\SecureBoot-Readiness-Advisor.ps1 -Mode User -OpenReport
```

For a fuller technician report:

```powershell
.\SecureBoot-Readiness-Advisor.ps1 -Mode Technician
```

For an ESU-enrolled Windows 10 workstation:

```powershell
.\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -Windows10EsuStatus Enrolled -OpenReport
```

For the optional guided local experience:

```powershell
.\SecureBoot-Readiness-Advisor.ps1 -Interactive
```

For fleet/RMM-style output:

```powershell
.\SecureBoot-Readiness-Advisor.ps1 -Mode Fleet -OutputDirectory C:\ProgramData\SecureBootAdvisor
```

## Output files

The script writes reports to the selected output directory:

- `SecureBootAdvisor-COMPUTER-TIMESTAMP.html`
- `SecureBootAdvisor-COMPUTER-TIMESTAMP.json`
- `SecureBootAdvisor-COMPUTER-TIMESTAMP.txt`
- `SecureBootAdvisor-COMPUTER-TIMESTAMP-summary.csv`
- `SecureBootAdvisor-COMPUTER-TIMESTAMP-findings.csv`

The HTML report is designed for normal human review. The JSON and CSV files are designed for technicians, fleet review, and later tooling.

## Advisor states

The tool can return these overall statuses:

| Status | Meaning |
|---|---|
| `Ready` | No major readiness blockers were detected. |
| `ReviewRecommended` | The device may be fine, but one or more signals require review. |
| `ActionRequired` | A meaningful remediation or support-path issue was detected. |
| `Unsupported` | The current boot/support posture blocks normal Secure Boot readiness. |
| `PossibleIntegrityIssue` | Boot integrity signals require investigation before remediation. |
| `InsufficientPermissions` | Rerun elevated for a reliable result. |
| `Unknown` | The advisor lacked enough evidence to classify confidently. |

## Common remediation guidance

### Legacy BIOS mode

Secure Boot requires UEFI. Back up the system, confirm recovery media, verify disk layout, evaluate MBR2GPT only if appropriate, switch firmware to UEFI, enable Secure Boot, and rerun the advisor.

### Secure Boot disabled

Confirm BitLocker recovery key backup first. Then enable Secure Boot in firmware setup, reboot, and rerun the advisor.

### 2023 certificate signal missing or unknown

Install current Windows cumulative updates, apply the latest OEM BIOS/UEFI firmware, reboot, and rerun. If still unclear, review Microsoft and OEM deployment guidance.

### BitLocker currently enabled

Confirm recovery key escrow or backup before firmware, Secure Boot, DBX, or boot manager changes. In managed environments, verify Entra ID, Active Directory, MBAM, or endpoint management escrow.

### BitLocker Secure Boot integrity warning events

Review BitLocker Event ID 815 or related integrity warnings as historical or current firmware/TPM/Secure Boot measurement signals. If BitLocker is currently off, no BitLocker-specific remediation is indicated unless it will be re-enabled. If BitLocker is on or will be re-enabled, confirm recovery key escrow, apply relevant OEM firmware updates, reboot, and rerun the advisor.

### Windows 10 ESU / servicing path review

If ESU is user-confirmed or post-EOS update evidence is present, keep ESU active, verify final enrollment in Windows Update settings, keep Windows/OEM firmware current, and rerun after monthly updates. If ESU is not enrolled, enroll if eligible or upgrade to Windows 11 where possible.

### Linux dual-boot suspected

Update the Linux distribution, shim, GRUB, and firmware first. Confirm the distro supports the newer Secure Boot chain before applying revocation or certificate changes.

### Boot manager signature invalid

Stop. Do not start Secure Boot certificate remediation. Run offline malware scanning, validate BCD/boot files, run SFC/DISM, and escalate to incident response if unexpected.

## Parameters

| Parameter | Description |
|---|---|
| `-Mode User` | Concise report intended for normal users. |
| `-Mode Technician` | Fuller local report with technical evidence. |
| `-Mode Fleet` | Emits compressed JSON to stdout for tooling. |
| `-OutputDirectory` | Selects where reports are written. |
| `-Redact` | Redacts common sensitive values. Enabled by default. Use `-Redact:$false` only when needed. |
| `-IncludeLicenseDetails` | Captures `slmgr /dlv` output to a separate file and extracts possible ESU lines. Disabled by default. |
| `-SkipEspMount` | Skips temporary EFI System Partition mounting. |
| `-EspDriveLetter` | Sets the temporary ESP mount drive letter. Default: `S`. |
| `-EventLogDays` | Number of days of relevant event log warnings/errors to inspect. Default: `30`. |
| `-OpenReport` | Opens the HTML report after completion. |
| `-Interactive` | Opens the optional Windows Forms guided prompt. Not used in Fleet mode. |
| `-Windows10EsuStatus` | Optional user-declared ESU state: `Unknown`, `Enrolled`, or `NotEnrolled`. |


## Script readability / markup

The script is intentionally marked up for human review. It uses PowerShell `#region` / `#endregion` blocks and function banners so admins can quickly identify what each section does. The main sections are:

1. Runtime setup and global state
2. Console and display helpers
3. Privacy, object, and severity helpers
4. Optional interactive UI helpers
5. Finding and collection-warning helpers
6. Evidence collectors
7. Windows support and certificate-refresh context
8. Advisor rules and assessment
9. Report generation
10. Main execution

Each function includes a short `Purpose` and `Safety` note. This is meant to make the project easier to inspect, fork, and trust before use.

## Notes on certificate detection

The script attempts a simple text scan of readable Secure Boot UEFI variables for known Microsoft 2023 and 2011 certificate strings. This is useful as an advisory signal, but it is not a full binary UEFI signature database parser. Treat missing text matches as a review signal, not proof that the newer certificates are absent.

## Recommended GitHub description

> Read-only PowerShell advisor for auditing Windows Secure Boot readiness, BitLocker risk, TPM state, boot manager signature, firmware posture, and 2026 Secure Boot certificate transition signals.

## Suggested repository topics

`powershell`, `secure-boot`, `uefi`, `windows-security`, `bitlocker`, `tpm`, `firmware`, `endpoint-management`, `intune`, `sysadmin`

## License

MIT is recommended for easy public reuse. Review before publishing if your employer, client, or prior work product could create ownership concerns.

## v2.0.16 reporting note

The advisor no longer uses a numeric readiness score. Secure Boot certificate readiness is not a precise percentage because Microsoft certificate deployment is phased, device targeting can vary, and UEFI signature data may not expose readable certificate strings. Reports now use categorical readiness rationale instead: positive signals, informational items, review items, and action items.

