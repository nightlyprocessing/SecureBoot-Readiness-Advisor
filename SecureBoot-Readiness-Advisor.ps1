<#
.SYNOPSIS
    Secure Boot Readiness Advisor for the 2026 Secure Boot certificate refresh.

.DESCRIPTION
    Audits Secure Boot readiness, firmware mode, TPM, BitLocker risk, boot manager signature,
    Secure Boot registry indicators, UEFI variable signals, recent relevant events, firmware age,
    and Windows support posture. Produces deterministic recommendations without changing firmware
    or Secure Boot configuration.

    This tool is intentionally read-only. It does not enable Secure Boot, modify UEFI variables,
    suspend BitLocker, alter boot configuration, or install updates.

.PARAMETER OutputDirectory
    Directory where reports are written. Defaults to the current user's Downloads folder.

.PARAMETER Mode
    User: concise output and HTML advisor report.
    Technician: fuller local report with technical evidence.
    Fleet: writes reports and emits compressed JSON to stdout for RMM/Intune/ConfigMgr ingestion.

.PARAMETER Redact
    Redacts common sensitive values from generated reports. Enabled by default.
    Use -Redact:$false only when you intentionally want local, unredacted evidence.

.PARAMETER IncludeLicenseDetails
    Captures slmgr /dlv output to a separate file and extracts possible ESU-related lines.
    Disabled by default because licensing output may contain environment-specific identifiers.

.PARAMETER Windows10EsuStatus
    Optional Windows 10 ESU enrollment hint: Auto, Unknown, Enrolled, or NotEnrolled. Auto performs best-effort local checks but still cannot independently prove consumer ESU enrollment.
    This is advisory input only. The tool does not independently prove consumer ESU enrollment.

.PARAMETER SkipEspMount
    Skips temporary mounting of the EFI System Partition.

.PARAMETER EspDriveLetter
    Drive letter to use if the EFI System Partition is temporarily mounted. Defaults to S.

.PARAMETER EventLogDays
    Number of days of event logs to inspect for relevant warnings/errors. Defaults to 30.

.PARAMETER MaxEventsPerLog
    Maximum events to inspect per log. Defaults to 80.

.PARAMETER OpenReport
    Opens the generated HTML report after completion.

.PARAMETER Interactive
    Opens a lightweight Windows Forms prompt for local, manual runs. This is optional and is not used in Fleet mode.

.PARAMETER CreateBundle
    Creates a local ZIP handoff bundle containing generated report files, a manifest, and SHA256 hashes.
    This tool does not upload or transmit the bundle.

.PARAMETER BundleIncludesSensitive
    Includes sensitive local-only files, such as the raw slmgr license dump and transcript, in the ZIP bundle.
    Disabled by default. Use only when your organization explicitly wants those files included.

.PARAMETER BundlePath
    Optional output ZIP path or output directory for the bundle. If omitted, the bundle is created in OutputDirectory.

.PARAMETER CaseId
    Optional case, ticket, wave, pilot, or change identifier to include in the bundle name and manifest.

.PARAMETER NoTranscript
    Suppresses transcript capture. Useful for automation or when transcripts are not desired.

.PARAMETER NoHtml
    Suppresses HTML report generation.

.PARAMETER NoJson
    Suppresses JSON report generation.

.PARAMETER NoCsv
    Suppresses CSV report generation.

.PARAMETER Explain
    Prints a plain-English explanation of what the advisor checks and how to interpret results, then exits.

.SCRIPT ARCHITECTURE
    The script is organized into readable sections using PowerShell #region markers:

    1. Runtime setup and global state
       Initializes strict mode, global findings, warning collections, and redaction state.

    2. Console and display helpers
       Writes readable console output without affecting Fleet mode JSON output.

    3. Privacy, object, and severity helpers
       Handles redaction, HTML-safe text, consistent PSObject creation, and severity ranking.

    4. Optional interactive UI helpers
       Provides lightweight Windows Forms prompts for manual/local users.

    5. Finding and collection-warning helpers
       Normalizes advisor findings and non-fatal collection gaps.

    6. Evidence collectors
       Collects OS, firmware, Secure Boot, UEFI variable, boot manager, BitLocker, TPM, event log, and update evidence.

    7. Windows support and certificate-refresh context
       Interprets Windows 10 ESU/user-declared support posture and phased certificate rollout state.

    8. Advisor rules and assessment
       Converts raw evidence into deterministic findings, risk, status, confidence, and next action.

    9. Report generation and handoff bundling
       Produces TXT, HTML, JSON, CSV, optional ZIP bundle, manifest, SHA256 hashes, and handoff README.

    10. Executive summaries and applicable guidance
       Adds human-readable posture, categorical readiness rationale, conditional remediation, and top event details.

    10. Main execution
       Coordinates collection, assessment, reporting, optional dialog display, and transcript cleanup.

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode User -OpenReport

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -IncludeLicenseDetails

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -Windows10EsuStatus Enrolled

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode Fleet -OutputDirectory C:\ProgramData\SecureBootAdvisor

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -CreateBundle -CaseId "SECBOOT-2026-PILOT"

.EXAMPLE
    .\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -IncludeLicenseDetails -CreateBundle -BundleIncludesSensitive

.NOTES
    Version: 2.0.16
    Author: Joe Miglio
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads"),

    [Parameter(Mandatory = $false)]
    [ValidateSet("User", "Technician", "Fleet")]
    [string]$Mode = "Technician",

    [Parameter(Mandatory = $false)]
    [bool]$Redact = $true,

    [Parameter(Mandatory = $false)]
    [switch]$NoTranscript,

    [Parameter(Mandatory = $false)]
    [switch]$NoHtml,

    [Parameter(Mandatory = $false)]
    [switch]$NoJson,

    [Parameter(Mandatory = $false)]
    [switch]$NoCsv,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLicenseDetails,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Auto", "Unknown", "Enrolled", "NotEnrolled")]
    [string]$Windows10EsuStatus = "Auto",

    [Parameter(Mandatory = $false)]
    [switch]$SkipEspMount,

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[A-Z]$")]
    [string]$EspDriveLetter = "S",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$EventLogDays = 30,

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 2000)]
    [int]$MaxEventsPerLog = 80,

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport,

    [Parameter(Mandatory = $false)]
    [switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [switch]$CreateBundle,

    [Parameter(Mandatory = $false)]
    [switch]$BundleIncludesSensitive,

    [Parameter(Mandatory = $false)]
    [string]$BundlePath,

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[A-Za-z0-9_. -]{0,80}$")]
    [string]$CaseId,

    [Parameter(Mandatory = $false)]
    [switch]$Explain
)

#region Runtime setup and global state
# Purpose: initialize script-wide behavior, output state, findings, warnings, and redaction tokens.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$script:ToolName = "Secure Boot Readiness Advisor"
$script:ToolVersion = "2.0.16"
$script:Findings = @()
$script:FindingCounter = 0
$script:CollectionWarnings = @()
$script:CollectionWarningCounter = 0
$script:SensitiveTokens = @()

#endregion Runtime setup and global state

#region Console and display helpers
# Purpose: centralize console formatting so normal runs are readable and Fleet mode stays machine-friendly.
# -----------------------------------------------------------------------------
# Function: Write-Console
# Purpose : Writes console messages while suppressing normal text output in Fleet mode.
# Safety  : Presentation only.
# -----------------------------------------------------------------------------

function Write-Console {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $false)][string]$ForegroundColor = "Gray"
    )

    if ($Mode -ne "Fleet") {
        if ([string]::IsNullOrEmpty($Message)) {
            Write-Host ""
        }
        else {
            Write-Host $Message -ForegroundColor $ForegroundColor
        }
    }
}

# -----------------------------------------------------------------------------
# Function: Write-Section
# Purpose : Writes a formatted console section heading for interactive/technician readability.
# Safety  : Presentation only.
# -----------------------------------------------------------------------------

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)

    if ($Mode -ne "Fleet") {
        Write-Host ""
        Write-Host ("=" * 78) -ForegroundColor DarkGray
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ("=" * 78) -ForegroundColor DarkGray
    }
}

#endregion Console and display helpers

#region Privacy, object, and severity helpers
# Purpose: support safe reporting, redaction, HTML encoding, object creation, and deterministic severity sorting.
# -----------------------------------------------------------------------------
# Function: Test-IsAdministrator
# Purpose : Determines whether the current PowerShell session is elevated.
# Safety  : Read-only Windows identity check.
# -----------------------------------------------------------------------------

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# -----------------------------------------------------------------------------
# Function: Add-SensitiveToken
# Purpose : Stores sensitive values discovered during collection so later reports can redact them.
# Safety  : Does not transmit or persist tokens outside generated local reports.
# -----------------------------------------------------------------------------

function Add-SensitiveToken {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if ($Value.Length -lt 3) { return }
    if (-not $script:SensitiveTokens.Contains($Value)) {
        $script:SensitiveTokens += $Value
    }
}

# -----------------------------------------------------------------------------
# Function: Protect-String
# Purpose : Redacts usernames, product-key-like strings, BitLocker recovery-password patterns, GUIDs, and collected sensitive tokens.
# Safety  : Report-safety helper.
# -----------------------------------------------------------------------------

function Protect-String {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) { return $null }
    if (-not $Redact) { return $Value }

    $result = [string]$Value

    foreach ($token in $script:SensitiveTokens) {
        if (-not [string]::IsNullOrWhiteSpace($token)) {
            $result = $result -replace [regex]::Escape($token), "<redacted>"
        }
    }

    $result = $result -replace 'C:\\Users\\[^\\\s]+', 'C:\Users\<redacted>'
    $result = $result -replace '([A-Z0-9]{5}-){4}[A-Z0-9]{5}', '<product-key-redacted>'
    $result = $result -replace '\b\d{6}(-\d{6}){7}\b', '<bitlocker-recovery-password-redacted>'
    $result = $result -replace '\b[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}\b', '<guid-redacted>'

    return $result
}

# -----------------------------------------------------------------------------
# Function: ConvertTo-HtmlSafe
# Purpose : Redacts and HTML-encodes values before inserting them into the HTML report.
# Safety  : Prevents accidental HTML injection in generated local reports.
# -----------------------------------------------------------------------------

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "" }
    $text = Protect-String -Value ([string]$Value)
    return [System.Net.WebUtility]::HtmlEncode($text)
}

function ConvertTo-DisplayLabel {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "" }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return "" }

    $known = @{
        "ReviewRecommended" = "Review Recommended"
        "ActionRequired" = "Action Required"
        "PossibleIntegrityIssue" = "Possible Integrity Issue"
        "InsufficientPermissions" = "Insufficient Permissions"
        "NotConfirmedReadableUefiData" = "Not Confirmed - Readable UEFI Data"
        "UnknownUefiDataNotReadable" = "Unknown - UEFI Data Not Readable"
        "EligibleWindows10EsuUserConfirmed" = "Eligible - Windows 10 ESU User Confirmed"
        "EligibleWindows10EsuSignalDetected" = "Eligible - Windows 10 ESU Signal Detected"
        "EligibleWindows10PostEosUpdateEvidenceDetected" = "Eligible - Windows 10 Post-EOS Update Evidence Detected"
        "PotentiallyEligibleWindows10EsuVerificationNeeded" = "Potentially Eligible - Windows 10 ESU Verification Needed"
        "NotEligibleWindows10NoEsuReported" = "Not Eligible - Windows 10 No ESU Reported"
        "NotConfirmedPossiblyUnsupported" = "Not Confirmed - Possibly Unsupported"
        "SupportedDesktop" = "Supported Desktop"
        "Windows10EsuUserConfirmed" = "Windows 10 ESU User Confirmed"
        "Windows10EsuSignalDetected" = "Windows 10 ESU Signal Detected"
        "Windows10PostEosUpdateEvidenceDetected" = "Windows 10 Post-EOS Update Evidence Detected"
        "Windows10EsuNotChecked" = "Windows 10 ESU Not Checked"
        "Windows10EsuNotConfirmed" = "Windows 10 ESU Not Confirmed"
        "Windows10NoEsuUserReported" = "Windows 10 No ESU Reported"
        "NotLocallyConfirmed" = "Not Locally Confirmed"
    }

    if ($known.ContainsKey($text)) { return $known[$text] }

    $spaced = $text -replace '([a-z0-9])([A-Z])', '$1 $2'
    $spaced = $spaced -replace '([A-Z]+)([A-Z][a-z])', '$1 $2'
    return $spaced
}

# -----------------------------------------------------------------------------
# Function: Get-SeverityRank
# Purpose : Maps finding severity names to numeric ranks for deterministic sorting.
# Safety  : Pure helper function.
# -----------------------------------------------------------------------------

function Get-SeverityRank {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return 5 }
        "High"     { return 4 }
        "Medium"   { return 3 }
        "Low"      { return 2 }
        "Info"     { return 1 }
        default     { return 0 }
    }
}


# -----------------------------------------------------------------------------
# Function: New-AdvisorObject
# Purpose : Creates PSObject instances in a Windows PowerShell 5.1-friendly way.
# Safety  : Avoids fragile pscustomobject/list behavior on older hosts.
# -----------------------------------------------------------------------------

function New-AdvisorObject {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Properties
    )

    $object = New-Object -TypeName PSObject
    foreach ($key in $Properties.Keys) {
        $object | Add-Member -MemberType NoteProperty -Name ([string]$key) -Value $Properties[$key] -Force
    }
    return $object
}


# -----------------------------------------------------------------------------
# Function: Show-AdvisorExplanation
# Purpose : Prints a plain-English explanation of what the tool does and how admins should interpret it.
# Safety  : Informational only. No collection or remediation.
# -----------------------------------------------------------------------------

function Show-AdvisorExplanation {
    $lines = @(
        "Secure Boot Readiness Advisor - explanation",
        "",
        "Purpose:",
        "  This tool helps admins separate boot health, Windows servicing eligibility, certificate rollout evidence, and remediation safety signals.",
        "",
        "What it checks:",
        "  - Firmware mode: UEFI vs. legacy BIOS",
        "  - Secure Boot enabled/disabled state",
        "  - Windows boot manager signature status",
        "  - TPM readiness",
        "  - BitLocker recovery-risk context",
        "  - Windows support and Windows 10 ESU posture",
        "  - Secure Boot registry/update indicators",
        "  - Readable UEFI variable text signals for older/newer Microsoft certificate strings",
        "  - Recent relevant event log warnings/errors",
        "",
        "What it does not do:",
        "  - It does not modify firmware, UEFI variables, DBX, BitLocker, BCD, Secure Boot settings, or Windows Update.",
        "  - It performs best-effort local ESU checks by default, but Windows Update Settings remains the user-facing enrollment source of truth.",
        "  - It does not prove consumer ESU enrollment unless Microsoft exposes a local signal the tool can read.",
        "  - It does not guarantee a specific Microsoft certificate rollout date for a device.",
        "",
        "How to interpret 'certificate not confirmed':",
        "  That does not automatically mean failure. Microsoft uses a phased Windows Update rollout and UEFI signature data is binary, so a simple text scan may not confirm the final state.",
        "",
        "Recommended admin use:",
        "  1. Confirm Windows servicing path, especially Windows 10 ESU enrollment.",
        "  2. Confirm BitLocker recovery key escrow before firmware or Secure Boot changes.",
        "  3. Apply monthly Windows updates and OEM firmware updates.",
        "  4. Reboot and rerun the advisor.",
        "  5. Use the HTML/JSON/CSV outputs for review or fleet tracking.",
        "",
        "Example:",
        '  .\SecureBoot-Readiness-Advisor.ps1 -Mode Technician -Windows10EsuStatus Enrolled -IncludeLicenseDetails -CreateBundle -CaseId "SECBOOT-2026-TEST" -OpenReport'
    )

    foreach ($line in $lines) { Write-Output $line }
}


#endregion Privacy, object, and severity helpers

#region Optional interactive UI helpers
# Purpose: provide a lightweight Windows Forms experience for local users without changing CLI/Fleet behavior.
# -----------------------------------------------------------------------------
# Function: Invoke-AdvisorInteractivePrompt
# Purpose : Displays the optional startup dialog for User/Technician mode, ESU status, license collection, and report opening choices.
# Safety  : UI only. No remediation.
# -----------------------------------------------------------------------------

function Invoke-AdvisorInteractivePrompt {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentMode,
        [Parameter(Mandatory = $true)][string]$CurrentWindows10EsuStatus,
        [Parameter(Mandatory = $true)][bool]$CurrentIncludeLicenseDetails,
        [Parameter(Mandatory = $true)][bool]$CurrentOpenReport
    )

    $fallback = New-AdvisorObject -Properties ([ordered]@{
        Mode                  = $CurrentMode
        Windows10EsuStatus    = $CurrentWindows10EsuStatus
        IncludeLicenseDetails = $CurrentIncludeLicenseDetails
        OpenReport            = $CurrentOpenReport
        Cancelled             = $false
    })

    if ($CurrentMode -eq "Fleet") { return $fallback }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
        [System.Windows.Forms.Application]::EnableVisualStyles()

        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Secure Boot Readiness Advisor"
        $form.Size = New-Object System.Drawing.Size(560, 350)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.TopMost = $true

        $title = New-Object System.Windows.Forms.Label
        $title.Text = "Secure Boot Readiness Advisor"
        $title.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
        $title.AutoSize = $true
        $title.Location = New-Object System.Drawing.Point(18, 16)
        $form.Controls.Add($title)

        $description = New-Object System.Windows.Forms.Label
        $description.Text = "This read-only tool collects Secure Boot, Windows servicing, BitLocker, TPM, firmware, and certificate rollout signals. It does not remediate or change firmware settings."
        $description.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $description.Size = New-Object System.Drawing.Size(505, 45)
        $description.Location = New-Object System.Drawing.Point(20, 50)
        $form.Controls.Add($description)

        $modeLabel = New-Object System.Windows.Forms.Label
        $modeLabel.Text = "Report mode"
        $modeLabel.AutoSize = $true
        $modeLabel.Location = New-Object System.Drawing.Point(20, 105)
        $form.Controls.Add($modeLabel)

        $modeBox = New-Object System.Windows.Forms.ComboBox
        $modeBox.DropDownStyle = "DropDownList"
        [void]$modeBox.Items.Add("User")
        [void]$modeBox.Items.Add("Technician")
        $modeBox.SelectedItem = if ($CurrentMode -eq "User") { "User" } else { "Technician" }
        $modeBox.Location = New-Object System.Drawing.Point(185, 101)
        $modeBox.Width = 320
        $form.Controls.Add($modeBox)

        $esuLabel = New-Object System.Windows.Forms.Label
        $esuLabel.Text = "Windows 10 ESU status"
        $esuLabel.AutoSize = $true
        $esuLabel.Location = New-Object System.Drawing.Point(20, 142)
        $form.Controls.Add($esuLabel)

        $esuBox = New-Object System.Windows.Forms.ComboBox
        $esuBox.DropDownStyle = "DropDownList"
        [void]$esuBox.Items.Add("Auto")
        [void]$esuBox.Items.Add("Unknown")
        [void]$esuBox.Items.Add("Enrolled")
        [void]$esuBox.Items.Add("NotEnrolled")
        $esuBox.SelectedItem = $CurrentWindows10EsuStatus
        $esuBox.Location = New-Object System.Drawing.Point(185, 138)
        $esuBox.Width = 320
        $form.Controls.Add($esuBox)

        $licenseCheck = New-Object System.Windows.Forms.CheckBox
        $licenseCheck.Text = "Collect slmgr /dlv licensing details to separate file"
        $licenseCheck.Checked = $CurrentIncludeLicenseDetails
        $licenseCheck.AutoSize = $true
        $licenseCheck.Location = New-Object System.Drawing.Point(185, 175)
        $form.Controls.Add($licenseCheck)

        $openCheck = New-Object System.Windows.Forms.CheckBox
        $openCheck.Text = "Open HTML report when finished"
        $openCheck.Checked = $CurrentOpenReport
        $openCheck.AutoSize = $true
        $openCheck.Location = New-Object System.Drawing.Point(185, 205)
        $form.Controls.Add($openCheck)

        $note = New-Object System.Windows.Forms.Label
        $note.Text = "Warning: leave ESU as Unknown unless you have verified enrollment in Windows Update settings. Declaring ESU status is advisory input, not proof."
        $note.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $note.Size = New-Object System.Drawing.Size(505, 40)
        $note.Location = New-Object System.Drawing.Point(20, 240)
        $form.Controls.Add($note)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "Run advisor"
        $okButton.Width = 105
        $okButton.Location = New-Object System.Drawing.Point(300, 282)
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"
        $cancelButton.Width = 95
        $cancelButton.Location = New-Object System.Drawing.Point(415, 282)
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $dialogResult = $form.ShowDialog()
        if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
            $fallback.Cancelled = $true
            return $fallback
        }

        return New-AdvisorObject -Properties ([ordered]@{
            Mode                  = [string]$modeBox.SelectedItem
            Windows10EsuStatus    = [string]$esuBox.SelectedItem
            IncludeLicenseDetails = [bool]$licenseCheck.Checked
            OpenReport            = [bool]$openCheck.Checked
            Cancelled             = $false
        })
    }
    catch {
        Add-CollectionWarning -Check "Interactive prompt" -Detail "Windows Forms prompt could not be displayed: $($_.Exception.Message)" -Recommendation "Continue with command-line parameters or rerun without -Interactive."
        return $fallback
    }
}


# -----------------------------------------------------------------------------
# Function: Show-AdvisorCompletionDialog
# Purpose : Displays the optional completion dialog summarizing status, risk, and report path.
# Safety  : UI only. No remediation.
# -----------------------------------------------------------------------------

function Show-AdvisorCompletionDialog {
    param(
        [Parameter(Mandatory = $true)]$Audit,
        [Parameter(Mandatory = $false)][string]$HtmlReportPath
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $message = @(
            "Assessment complete.",
            "",
            "Status: $($Audit.Overall.Status)",
            "Risk: $($Audit.Overall.RiskLevel)",
            "Confidence: $($Audit.Overall.Confidence)",
            "",
            "Secure Boot: $($Audit.SecureBoot.Enabled)",
            "Windows path: $($Audit.WindowsSupport.ServicingPathSummary)",
            "Certificate rollout: $($Audit.CertificateRefresh.DeploymentState)",
            "",
            "Next action:",
            "$($Audit.Overall.NextAction)",
            ""
        )
        if (-not [string]::IsNullOrWhiteSpace($HtmlReportPath)) {
            $message += "HTML report: $HtmlReportPath"
        }
        [void][System.Windows.Forms.MessageBox]::Show(($message -join [Environment]::NewLine), "Secure Boot Readiness Advisor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    catch {
        # Dialogs are optional. Do not fail the advisor if Windows Forms is unavailable.
    }
}

#endregion Optional interactive UI helpers

#region Finding and collection-warning helpers
# Purpose: normalize findings and non-fatal collection gaps so reports are consistent and easy to review.
# -----------------------------------------------------------------------------
# Function: Add-Finding
# Purpose : Adds a normalized advisor finding with severity, category, evidence, and recommendation.
# Safety  : Data shaping only.
# -----------------------------------------------------------------------------

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Low", "Medium", "High", "Critical")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Detail,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation,

        [Parameter(Mandatory = $false)]
        [string]$Evidence = ""
    )

    $script:FindingCounter++

    $finding = (New-AdvisorObject -Properties ([ordered]@{
        Id             = $script:FindingCounter
        Severity       = $Severity
        SeverityRank   = (Get-SeverityRank -Severity $Severity)
        Category       = $Category
        Title          = $Title
        Detail         = (Protect-String -Value $Detail)
        Recommendation = (Protect-String -Value $Recommendation)
        Evidence       = (Protect-String -Value $Evidence)
    }))

    $script:Findings += $finding
}

# -----------------------------------------------------------------------------
# Function: Add-CollectionWarning
# Purpose : Records non-fatal evidence collection gaps, such as unavailable event logs or missing registry values.
# Safety  : Used to explain confidence limitations.
# -----------------------------------------------------------------------------

function Add-CollectionWarning {
    param(
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Detail,
        [Parameter(Mandatory = $false)][string]$Recommendation = "Review the generated report and rerun elevated if this signal is needed for a higher-confidence assessment.",
        [Parameter(Mandatory = $false)][string]$Evidence = ""
    )

    $script:CollectionWarningCounter++

    $warning = (New-AdvisorObject -Properties ([ordered]@{
        Id             = $script:CollectionWarningCounter
        Check          = $Check
        Detail         = (Protect-String -Value $Detail)
        Recommendation = (Protect-String -Value $Recommendation)
        Evidence       = (Protect-String -Value $Evidence)
    }))

    $script:CollectionWarnings += $warning
}

#endregion Finding and collection-warning helpers

#region Evidence collectors
# Purpose: gather read-only system evidence. These functions should not remediate, write firmware, alter BitLocker, or change boot state.
# -----------------------------------------------------------------------------
# Function: Get-FirmwareMode
# Purpose : Determines firmware mode using PEFirmwareType when available, then falls back to BCDEdit/boot-loader evidence.
# Safety  : Read-only registry and command output inspection.
# -----------------------------------------------------------------------------

function Get-FirmwareMode {
    $mode = "Unknown"
    $raw = $null
    $errorText = $null
    $method = "Unknown"
    $confidence = "Low"

    # Primary Microsoft-documented signal. Some systems do not expose this value,
    # so absence is treated as a collection warning rather than a hard failure.
    try {
        $controlPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
        $control = Get-ItemProperty -Path $controlPath -ErrorAction SilentlyContinue
        if ($control -and ($control.PSObject.Properties.Name -contains "PEFirmwareType")) {
            $raw = $control.PEFirmwareType
            $mode = switch ($raw) {
                1 { "BIOS" }
                2 { "UEFI" }
                default { "Unknown($raw)" }
            }
            $method = "Registry:PEFirmwareType"
            $confidence = if ($mode -in @("BIOS", "UEFI")) { "High" } else { "Low" }
        }
        else {
            $errorText = "PEFirmwareType was not present under HKLM:\SYSTEM\CurrentControlSet\Control."
            Add-CollectionWarning -Check "Firmware mode" -Detail $errorText -Recommendation "The advisor will try fallback detection. Confirm firmware mode in System Information if the final result remains unclear."
        }
    }
    catch {
        $errorText = $_.Exception.Message
        Add-CollectionWarning -Check "Firmware mode" -Detail $errorText -Recommendation "Confirm firmware mode in System Information or firmware setup if the final result remains unclear."
    }

    # Fallback: Windows boot loader path. UEFI installations normally use winload.efi;
    # legacy BIOS installations normally use winload.exe.
    if ($mode -notin @("BIOS", "UEFI")) {
        try {
            $bcdOutput = & bcdedit.exe /enum "{current}" 2>$null
            $bcdText = ($bcdOutput -join "`n")
            if ($bcdText -match "winload\.efi") {
                $mode = "UEFI"
                $method = "BCDEdit:winload.efi"
                $confidence = "Medium"
            }
            elseif ($bcdText -match "winload\.exe") {
                $mode = "BIOS"
                $method = "BCDEdit:winload.exe"
                $confidence = "Medium"
            }
            elseif (-not [string]::IsNullOrWhiteSpace($bcdText)) {
                Add-CollectionWarning -Check "Firmware mode fallback" -Detail "BCDEdit output was readable, but no winload.efi or winload.exe signal was found." -Recommendation "Confirm firmware mode manually if Secure Boot state is unknown."
            }
        }
        catch {
            Add-CollectionWarning -Check "Firmware mode fallback" -Detail $_.Exception.Message -Recommendation "Confirm firmware mode manually if Secure Boot state is unknown."
        }
    }

    (New-AdvisorObject -Properties ([ordered]@{
        FirmwareType    = $mode
        RawValue        = $raw
        DetectionMethod = $method
        Confidence      = $confidence
        Error           = (Protect-String -Value $errorText)
    }))
}

# -----------------------------------------------------------------------------
# Function: Convert-WmiDate
# Purpose : Converts WMI/CIM datetime strings into .NET DateTime values.
# Safety  : Pure conversion helper.
# -----------------------------------------------------------------------------

function Convert-WmiDate {
    param([AllowNull()][string]$WmiDate)

    if ([string]::IsNullOrWhiteSpace($WmiDate)) { return $null }

    try {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiDate)
    }
    catch {
        return $null
    }
}

# -----------------------------------------------------------------------------
# Function: Get-SystemInventory
# Purpose : Collects OS, computer, model, BIOS/UEFI, build, and update baseline details.
# Safety  : Read-only CIM/registry collection.
# -----------------------------------------------------------------------------

function Get-SystemInventory {
    $os = $null
    $cs = $null
    $bios = $null
    $baseboard = $null

    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
    try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop } catch { }
    try { $baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop } catch { }

    if ($env:COMPUTERNAME) { Add-SensitiveToken -Value $env:COMPUTERNAME }
    if ($bios -and $bios.SerialNumber) { Add-SensitiveToken -Value $bios.SerialNumber }
    if ($cs -and $cs.Name) { Add-SensitiveToken -Value $cs.Name }

    $biosReleaseDate = $null
    $biosAgeDays = $null
    if ($bios) {
        $biosReleaseDate = Convert-WmiDate -WmiDate $bios.ReleaseDate
        if ($biosReleaseDate) {
            $biosAgeDays = [int]((Get-Date) - $biosReleaseDate).TotalDays
        }
    }

    (New-AdvisorObject -Properties ([ordered]@{
        ComputerName           = (Protect-String -Value $env:COMPUTERNAME)
        Manufacturer           = if ($cs) { Protect-String -Value $cs.Manufacturer } else { $null }
        Model                  = if ($cs) { Protect-String -Value $cs.Model } else { $null }
        SystemType             = if ($cs) { $cs.SystemType } else { $null }
        DomainRole             = if ($cs) { $cs.DomainRole } else { $null }
        OSName                 = if ($os) { $os.Caption } else { $null }
        OSVersion              = if ($os) { $os.Version } else { $null }
        BuildNumber            = if ($os) { $os.BuildNumber } else { $null }
        OSArchitecture         = if ($os) { $os.OSArchitecture } else { $null }
        ProductType            = if ($os) { $os.ProductType } else { $null }
        InstallDate            = if ($os) { Convert-WmiDate -WmiDate $os.InstallDate } else { $null }
        BIOSManufacturer       = if ($bios) { Protect-String -Value $bios.Manufacturer } else { $null }
        BIOSVersion            = if ($bios) { Protect-String -Value (($bios.BIOSVersion -join "; ")) } else { $null }
        SMBIOSBIOSVersion      = if ($bios) { Protect-String -Value $bios.SMBIOSBIOSVersion } else { $null }
        BIOSReleaseDate        = $biosReleaseDate
        BIOSAgeDays            = $biosAgeDays
        SerialNumber           = if ($bios) { Protect-String -Value $bios.SerialNumber } else { $null }
        BaseBoardManufacturer  = if ($baseboard) { Protect-String -Value $baseboard.Manufacturer } else { $null }
        BaseBoardProduct       = if ($baseboard) { Protect-String -Value $baseboard.Product } else { $null }
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-SecureBootState
# Purpose : Checks whether Secure Boot is enabled using Confirm-SecureBootUEFI.
# Safety  : Read-only Secure Boot query.
# -----------------------------------------------------------------------------

function Get-SecureBootState {
    $commandPresent = [bool](Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
    $result = $null
    $errorText = $null

    if ($commandPresent) {
        try {
            $secureBootErrors = @()
            $result = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue -ErrorVariable secureBootErrors
            if ($secureBootErrors -and $secureBootErrors.Count -gt 0) {
                $errorText = (($secureBootErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
                Add-CollectionWarning -Check "Secure Boot state" -Detail $errorText -Recommendation "Confirm the system is booted in UEFI mode and rerun elevated if Secure Boot state is required."
            }
        }
        catch {
            $errorText = $_.Exception.Message
            Add-CollectionWarning -Check "Secure Boot state" -Detail $errorText -Recommendation "Confirm the system is booted in UEFI mode and rerun elevated if Secure Boot state is required."
        }
    }
    else {
        $errorText = "Confirm-SecureBootUEFI is not available on this system."
        Add-CollectionWarning -Check "Secure Boot state" -Detail $errorText -Recommendation "Use a supported Windows environment or confirm Secure Boot state through firmware setup/System Information."
    }

    (New-AdvisorObject -Properties ([ordered]@{
        CommandPresent = $commandPresent
        Enabled        = $result
        Error          = (Protect-String -Value $errorText)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-SecureBootRegistryIndicators
# Purpose : Reads Windows Secure Boot servicing indicator registry values when present.
# Safety  : Read-only registry collection.
# -----------------------------------------------------------------------------

function Get-SecureBootRegistryIndicators {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    $readable = $false
    $errorText = $null
    $properties = @()
    $specific = [ordered]@{
        UEFICA2023Status         = $null
        UEFIRevocationListStatus = $null
        AvailableUpdates         = $null
        AttemptedUpdates         = $null
        LastUpdateTime           = $null
    }

    try {
        $reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($reg) {
            $readable = $true

            $properties = $reg.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object {
                    (New-AdvisorObject -Properties ([ordered]@{
                        Name  = $_.Name
                        Value = (Protect-String -Value ([string]$_.Value))
                    }))
                }

            foreach ($key in @($specific.Keys)) {
                if ($reg.PSObject.Properties.Name -contains $key) {
                    $specific[$key] = Protect-String -Value ([string]$reg.$key)
                }
            }
        }
        else {
            $errorText = "SecureBoot registry key was not found or was not readable: $path"
            Add-CollectionWarning -Check "Secure Boot registry" -Detail $errorText -Recommendation "This can happen on non-UEFI or unsupported systems. Use other evidence if Secure Boot registry signals are unavailable."
        }
    }
    catch {
        $errorText = $_.Exception.Message
        Add-CollectionWarning -Check "Secure Boot registry" -Detail $errorText -Recommendation "Rerun elevated and confirm the system is using UEFI firmware if this signal is required."
    }

    (New-AdvisorObject -Properties ([ordered]@{
        Path       = $path
        Readable   = $readable
        Error      = (Protect-String -Value $errorText)
        Specific   = (New-AdvisorObject -Properties $specific)
        Properties = $properties
    }))
}

# -----------------------------------------------------------------------------
# Function: Search-ByteArrayForText
# Purpose : Performs simple text-pattern checks against byte arrays from UEFI variable reads.
# Safety  : Advisory signal only, not a full binary signature database parser.
# -----------------------------------------------------------------------------

function Search-ByteArrayForText {
    param(
        [AllowNull()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $matches = @()
    if ($null -eq $Bytes -or $Bytes.Count -eq 0) { return @() }

    $ascii = ""
    $unicode = ""
    try { $ascii = [System.Text.Encoding]::ASCII.GetString($Bytes) } catch { }
    try { $unicode = [System.Text.Encoding]::Unicode.GetString($Bytes) } catch { }

    foreach ($pattern in $Patterns) {
        if ($ascii -match [regex]::Escape($pattern) -or $unicode -match [regex]::Escape($pattern)) {
            if ($matches -notcontains $pattern) { $matches += $pattern }
        }
    }

    return [string[]]$matches
}

# -----------------------------------------------------------------------------
# Function: Get-UefiVariableSignals
# Purpose : Attempts to read PK, KEK, db, and dbx Secure Boot variables and scan for known text markers.
# Safety  : Read-only UEFI variable reads.
# -----------------------------------------------------------------------------

function Get-UefiVariableSignals {
    $commandPresent = [bool](Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)
    $variables = @()
    $patterns = @(
        "Microsoft Corporation UEFI CA 2023",
        "Microsoft Windows UEFI CA 2023",
        "Windows UEFI CA 2023",
        "Microsoft Corporation UEFI CA 2011",
        "Microsoft Windows Production PCA 2011",
        "Microsoft Windows UEFI Driver Publisher",
        "Microsoft Windows Production PCA 2023"
    )

    if (-not $commandPresent) {
        Add-CollectionWarning -Check "UEFI variable collection" -Detail "Get-SecureBootUEFI is not available on this system." -Recommendation "Rerun on a supported Windows installation with the SecureBoot module available, or rely on registry/update/OEM evidence."
        return (New-AdvisorObject -Properties ([ordered]@{
            CommandPresent      = $false
            Variables           = @()
            Detected2023Pattern = $false
            Detected2011Pattern = $false
            ReadableCount       = 0
            Error               = "Get-SecureBootUEFI is not available on this system."
        }))
    }

    foreach ($name in @("PK", "KEK", "db", "dbx")) {
        $readable = $false
        $byteCount = $null
        $errorText = $null
        $matches = @()
        $attributes = $null

        try {
            $secureBootErrors = @()
            # Windows PowerShell 5.1's Get-SecureBootUEFI does not accept -Namespace.
            # The standard Secure Boot namespace is handled internally by the cmdlet.
            $value = Get-SecureBootUEFI -Name $name -ErrorAction SilentlyContinue -ErrorVariable secureBootErrors
            if ($value) {
                $readable = $true
                $bytes = $value.Bytes
                if ($bytes) { $byteCount = $bytes.Count } else { $byteCount = 0 }
                $attributes = Protect-String -Value ([string]$value.Attributes)
                $matches = Search-ByteArrayForText -Bytes $bytes -Patterns $patterns
            }
            else {
                $errorText = (($secureBootErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
                if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "No value returned by Get-SecureBootUEFI." }
            }
        }
        catch {
            $errorText = $_.Exception.Message
        }

        if (-not $readable) {
            Add-CollectionWarning -Check "UEFI variable $name" -Detail "The $name Secure Boot variable could not be read. $errorText" -Recommendation "Rerun elevated on UEFI Windows. If this remains unavailable, use Windows servicing, OEM firmware guidance, and firmware setup evidence."
        }

        $variableRecord = New-Object -TypeName psobject
        $variableRecord | Add-Member -MemberType NoteProperty -Name Name -Value $name
        $variableRecord | Add-Member -MemberType NoteProperty -Name Readable -Value $readable
        $variableRecord | Add-Member -MemberType NoteProperty -Name ByteCount -Value $byteCount
        $variableRecord | Add-Member -MemberType NoteProperty -Name TextMatches -Value ([string[]]@($matches))
        $variableRecord | Add-Member -MemberType NoteProperty -Name Attributes -Value $attributes
        $variableRecord | Add-Member -MemberType NoteProperty -Name Error -Value (Protect-String -Value $errorText)
        $variables += $variableRecord
    }

    $allMatches = @($variables | ForEach-Object { @($_.TextMatches) } | Where-Object { $_ })
    $detected2023 = [bool]($allMatches | Where-Object { $_ -match "2023" } | Select-Object -First 1)
    $detected2011 = [bool]($allMatches | Where-Object { $_ -match "2011" } | Select-Object -First 1)
    $readableCount = @($variables | Where-Object { $_.Readable }).Count

    $result = New-Object -TypeName psobject
    $result | Add-Member -MemberType NoteProperty -Name CommandPresent -Value $true
    $result | Add-Member -MemberType NoteProperty -Name Variables -Value ([object[]]@($variables))
    $result | Add-Member -MemberType NoteProperty -Name Detected2023Pattern -Value $detected2023
    $result | Add-Member -MemberType NoteProperty -Name Detected2011Pattern -Value $detected2011
    $result | Add-Member -MemberType NoteProperty -Name ReadableCount -Value $readableCount
    $result | Add-Member -MemberType NoteProperty -Name Error -Value $null
    return $result
}

# -----------------------------------------------------------------------------
# Function: Get-BootManagerSignature
# Purpose : Locates the Windows boot manager and validates its Authenticode signature.
# Safety  : May temporarily mount the ESP unless skipped, then unmounts it.
# -----------------------------------------------------------------------------

function Get-BootManagerSignature {
    param(
        [string]$DriveLetter = "S",
        [switch]$SkipMount
    )

    $windowsBootPath = Join-Path $env:windir "Boot\EFI\bootmgfw.efi"
    $espRoot = "$DriveLetter`:"
    $espBootPath = "$espRoot\EFI\Microsoft\Boot\bootmgfw.efi"
    $paths = @($windowsBootPath, $espBootPath)

    $bootFile = $paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $mountedEsp = $false
    $mountSkippedReason = $null
    $mountError = $null

    if (-not $bootFile -and -not $SkipMount) {
        $driveExists = [bool](Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue)
        if ($driveExists) {
            $mountSkippedReason = "Drive $DriveLetter`: already exists. EFI System Partition was not mounted to avoid a collision."
        }
        else {
            try {
                cmd.exe /c "mountvol $DriveLetter`: /S" | Out-Null
                $mountedEsp = $true
                Start-Sleep -Milliseconds 500
                $bootFile = $paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            }
            catch {
                $mountError = $_.Exception.Message
            }
        }
    }
    elseif ($SkipMount) {
        $mountSkippedReason = "SkipEspMount was specified."
    }

    $sigStatus = $null
    $sigMessage = $null
    $signerSubject = $null
    $signerIssuer = $null
    $signerNotBefore = $null
    $signerNotAfter = $null
    $sigError = $null

    if ($bootFile) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $bootFile -ErrorAction Stop
            $sigStatus = [string]$sig.Status
            $sigMessage = Protect-String -Value $sig.StatusMessage

            if ($sig.SignerCertificate) {
                $signerSubject = Protect-String -Value $sig.SignerCertificate.Subject
                $signerIssuer = Protect-String -Value $sig.SignerCertificate.Issuer
                $signerNotBefore = $sig.SignerCertificate.NotBefore
                $signerNotAfter = $sig.SignerCertificate.NotAfter
            }
        }
        catch {
            $sigError = $_.Exception.Message
        }
    }

    if ($mountedEsp) {
        try { cmd.exe /c "mountvol $DriveLetter`: /D" | Out-Null } catch { }
    }

    (New-AdvisorObject -Properties ([ordered]@{
        BootFilePath       = (Protect-String -Value $bootFile)
        WindowsBootPath    = (Protect-String -Value $windowsBootPath)
        EspBootPath        = (Protect-String -Value $espBootPath)
        MountedEsp         = $mountedEsp
        MountSkippedReason = (Protect-String -Value $mountSkippedReason)
        MountError         = (Protect-String -Value $mountError)
        SignatureStatus    = $sigStatus
        SignatureMessage   = $sigMessage
        SignerSubject      = $signerSubject
        SignerIssuer       = $signerIssuer
        SignerNotBefore    = $signerNotBefore
        SignerNotAfter     = $signerNotAfter
        SignatureError     = (Protect-String -Value $sigError)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-BitLockerSummary
# Purpose : Summarizes BitLocker protection and recovery-password protector presence.
# Safety  : Read-only BitLocker status query.
# -----------------------------------------------------------------------------

function Get-BitLockerSummary {
    $commandPresent = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
    $volumes = @()
    $errorText = $null

    if (-not $commandPresent) {
        $errorText = "Get-BitLockerVolume is not available. This can happen on some Windows editions or PowerShell environments."
        Add-CollectionWarning -Check "BitLocker" -Detail $errorText -Recommendation "Manually confirm BitLocker state and recovery key backup before firmware or Secure Boot remediation."
        return (New-AdvisorObject -Properties ([ordered]@{
            CommandPresent = $false
            Error          = $errorText
            Volumes        = @()
        }))
    }

    try {
        $bitLockerErrors = @()
        $rawVolumes = @(Get-BitLockerVolume -ErrorAction SilentlyContinue -ErrorVariable bitLockerErrors)
        if (-not $rawVolumes -or $rawVolumes.Count -eq 0) {
            $errorText = (($bitLockerErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "Get-BitLockerVolume returned no volume data." }
            Add-CollectionWarning -Check "BitLocker" -Detail $errorText -Recommendation "Manually confirm BitLocker state and recovery key backup before firmware or Secure Boot remediation."
        }

        foreach ($volume in $rawVolumes) {
            $protectorTypes = @()
            $hasRecoveryPassword = $false

            if ($volume.KeyProtector) {
                foreach ($protector in $volume.KeyProtector) {
                    $protectorType = [string]$protector.KeyProtectorType
                    if ($protectorType) { $protectorTypes += $protectorType }
                    if ($protectorType -match "RecoveryPassword") { $hasRecoveryPassword = $true }
                }
            }

            $volumes += (New-AdvisorObject -Properties ([ordered]@{
                MountPoint                     = (Protect-String -Value ([string]$volume.MountPoint))
                VolumeStatus                   = [string]$volume.VolumeStatus
                ProtectionStatus               = [string]$volume.ProtectionStatus
                EncryptionMethod               = [string]$volume.EncryptionMethod
                EncryptionPercentage           = $volume.EncryptionPercentage
                LockStatus                     = [string]$volume.LockStatus
                KeyProtectorTypes              = (($protectorTypes | Sort-Object -Unique) -join "; ")
                RecoveryPasswordProtectorFound = $hasRecoveryPassword
            }))
        }
    }
    catch {
        $errorText = $_.Exception.Message
        Add-CollectionWarning -Check "BitLocker" -Detail $errorText -Recommendation "Manually confirm BitLocker state and recovery key backup before firmware or Secure Boot remediation."
    }

    (New-AdvisorObject -Properties ([ordered]@{
        CommandPresent = $true
        Error          = (Protect-String -Value $errorText)
        Volumes        = @($volumes)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-TpmSummary
# Purpose : Collects TPM presence, readiness, ownership, and manufacturer details.
# Safety  : Read-only TPM query.
# -----------------------------------------------------------------------------

function Get-TpmSummary {
    $commandPresent = [bool](Get-Command Get-Tpm -ErrorAction SilentlyContinue)
    $errorText = $null

    if (-not $commandPresent) {
        $errorText = "Get-Tpm is not available on this system."
        Add-CollectionWarning -Check "TPM" -Detail $errorText -Recommendation "Confirm TPM state manually if this device uses BitLocker, Windows Hello, Credential Guard, or Windows 11 readiness controls."
        return (New-AdvisorObject -Properties ([ordered]@{
            CommandPresent = $false
            Error          = $errorText
        }))
    }

    try {
        $tpmErrors = @()
        $tpm = Get-Tpm -ErrorAction SilentlyContinue -ErrorVariable tpmErrors
        if ($tpm) {
            return (New-AdvisorObject -Properties ([ordered]@{
                CommandPresent       = $true
                TpmPresent           = $tpm.TpmPresent
                TpmReady             = $tpm.TpmReady
                TpmEnabled           = $tpm.TpmEnabled
                TpmActivated         = $tpm.TpmActivated
                TpmOwned             = $tpm.TpmOwned
                ManufacturerIdTxt    = (Protect-String -Value $tpm.ManufacturerIdTxt)
                ManufacturerVersion  = (Protect-String -Value $tpm.ManufacturerVersion)
                ManagedAuthLevel     = (Protect-String -Value ([string]$tpm.ManagedAuthLevel))
                Error                = $null
            }))
        }
        else {
            $errorText = (($tpmErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "Get-Tpm returned no data." }
            Add-CollectionWarning -Check "TPM" -Detail $errorText -Recommendation "Confirm TPM state manually if this device uses BitLocker, Windows Hello, Credential Guard, or Windows 11 readiness controls."
        }
    }
    catch {
        $errorText = $_.Exception.Message
        Add-CollectionWarning -Check "TPM" -Detail $errorText -Recommendation "Confirm TPM state manually if this device uses BitLocker, Windows Hello, Credential Guard, or Windows 11 readiness controls."
    }

    return (New-AdvisorObject -Properties ([ordered]@{
        CommandPresent = $true
        Error          = (Protect-String -Value $errorText)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-DeviceGuardSummary
# Purpose : Collects Device Guard/VBS-related posture where available.
# Safety  : Read-only CIM query.
# -----------------------------------------------------------------------------

function Get-DeviceGuardSummary {
    $errorText = $null
    try {
        $dgErrors = @()
        $dg = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue -ErrorVariable dgErrors
        if ($dg) {
            return (New-AdvisorObject -Properties ([ordered]@{
                Readable                             = $true
                VirtualizationBasedSecurityStatus    = $dg.VirtualizationBasedSecurityStatus
                SecurityServicesConfigured           = ($dg.SecurityServicesConfigured -join "; ")
                SecurityServicesRunning              = ($dg.SecurityServicesRunning -join "; ")
                RequiredSecurityProperties           = ($dg.RequiredSecurityProperties -join "; ")
                AvailableSecurityProperties          = ($dg.AvailableSecurityProperties -join "; ")
                CodeIntegrityPolicyEnforcementStatus = $dg.CodeIntegrityPolicyEnforcementStatus
                UserModeCodeIntegrityPolicyStatus    = $dg.UserModeCodeIntegrityPolicyEnforcementStatus
                Error                                = $null
            }))
        }
        else {
            $errorText = (($dgErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "Device Guard/VBS WMI class returned no data." }
            Add-CollectionWarning -Check "Device Guard/VBS" -Detail $errorText -Recommendation "No action is required unless VBS/Device Guard evidence is needed for your assessment."
        }
    }
    catch {
        $errorText = $_.Exception.Message
        Add-CollectionWarning -Check "Device Guard/VBS" -Detail $errorText -Recommendation "No action is required unless VBS/Device Guard evidence is needed for your assessment."
    }

    return (New-AdvisorObject -Properties ([ordered]@{
        Readable = $false
        Error    = (Protect-String -Value $errorText)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-RecentHotfixSummary
# Purpose : Collects recent Windows hotfix/update records.
# Safety  : Read-only hotfix query.
# -----------------------------------------------------------------------------

function Get-RecentHotfixSummary {
    try {
        $hotFixErrors = @()
        $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue -ErrorVariable hotFixErrors)
        if (-not $hotfixes -or $hotfixes.Count -eq 0) {
            $errorText = (($hotFixErrors | ForEach-Object { $_.Exception.Message }) -join "; ")
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "Get-HotFix returned no data." }
            Add-CollectionWarning -Check "Hotfix inventory" -Detail $errorText -Recommendation "Confirm Windows Update history manually if servicing evidence is required."
            return @((New-AdvisorObject -Properties ([ordered]@{
                HotFixID    = "Unavailable"
                Description = (Protect-String -Value $errorText)
                InstalledOn = $null
                InstalledBy = $null
            })))
        }

        return @($hotfixes |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 20 |
            ForEach-Object {
                (New-AdvisorObject -Properties ([ordered]@{
                    HotFixID    = $_.HotFixID
                    Description = $_.Description
                    InstalledOn = $_.InstalledOn
                    InstalledBy = (Protect-String -Value $_.InstalledBy)
                }))
            })
    }
    catch {
        Add-CollectionWarning -Check "Hotfix inventory" -Detail $_.Exception.Message -Recommendation "Confirm Windows Update history manually if servicing evidence is required."
        return @((New-AdvisorObject -Properties ([ordered]@{
            HotFixID    = "Error"
            Description = (Protect-String -Value $_.Exception.Message)
            InstalledOn = $null
            InstalledBy = $null
        })))
    }
}

# -----------------------------------------------------------------------------
# Function: Get-RelevantEventSummary
# Purpose : Searches recent event logs for Secure Boot, BitLocker, TPM, UEFI, firmware, and boot-related warnings/errors.
# Safety  : Read-only event log query.
# -----------------------------------------------------------------------------

function Get-RelevantEventSummary {
    param(
        [int]$Days = 30,
        [int]$MaxEvents = 80
    )

    $logs = @(
        "Microsoft-Windows-Kernel-Boot/Operational",
        "Microsoft-Windows-BitLocker/BitLocker Management",
        "Microsoft-Windows-TPM-WMI/Operational",
        "System",
        "Setup"
    )

    $keywords = "Secure Boot|SecureBoot|BitLocker|TPM|dbx|UEFI|firmware|boot manager|bootmgfw|PCR7|recovery key"
    $startTime = (Get-Date).AddDays(-1 * $Days)
    $events = @()

    foreach ($log in $logs) {
        $logInfo = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
        if (-not $logInfo) {
            Add-CollectionWarning -Check "Event log: $log" -Detail "The event log was not available on this system." -Recommendation "No action is required unless this log is expected in your Windows edition or managed environment."
            continue
        }

        $rawEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $startTime; Level = 1, 2, 3 } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
        if (-not $rawEvents -or $rawEvents.Count -eq 0) {
            continue
        }

        foreach ($event in $rawEvents) {
            $message = [string]$event.Message
            if ($message -match $keywords -or $event.ProviderName -match "BitLocker|TPM|Kernel-Boot") {
                $events += (New-AdvisorObject -Properties ([ordered]@{
                    TimeCreated  = $event.TimeCreated
                    LogName      = $log
                    ProviderName = $event.ProviderName
                    Id           = $event.Id
                    LevelDisplay = $event.LevelDisplayName
                    Message      = (Protect-String -Value (($message -replace "`r|`n", " ").Trim()))
                }))
            }
        }
    }

    # De-duplicate on normalized event content rather than RecordId. Some logs can surface
    # near-identical entries with different internal record IDs, which is noisy in reports.
    $dedupedEvents = @{}
    foreach ($eventItem in $events) {
        $timeKey = ""
        if ($eventItem.TimeCreated) {
            try { $timeKey = ([datetime]$eventItem.TimeCreated).ToString("yyyy-MM-dd HH:mm:ss") } catch { $timeKey = [string]$eventItem.TimeCreated }
        }

        $messageKey = (([string]$eventItem.Message) -replace '\s+', ' ').Trim().ToLowerInvariant()
        $eventKey = "$timeKey|$($eventItem.LogName)|$($eventItem.ProviderName)|$($eventItem.Id)|$messageKey"

        if (-not $dedupedEvents.ContainsKey($eventKey)) {
            $dedupedEvents[$eventKey] = $eventItem
        }
    }

    return @(
        $dedupedEvents.Values |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 50
    )
}

#endregion Evidence collectors

#region Windows support and certificate-refresh context
# Purpose: interpret Windows servicing eligibility, ESU context, and phased Secure Boot certificate rollout state.
# -----------------------------------------------------------------------------
# Function: Get-WindowsSupportPosture
# Purpose : Interprets OS support posture, Windows 10 22H2 eligibility signals, user-declared ESU status, and optional license evidence.
# Safety  : Advisor logic only.
# -----------------------------------------------------------------------------

function Get-WindowsSupportPosture {
    param(
        [Parameter(Mandatory = $true)][object]$SystemInventory,
        [AllowNull()][string[]]$EsuLines,
        [bool]$LicenseDetailsCollected = $false,
        [AllowNull()][object[]]$RecentHotfixes = @(),
        [ValidateSet("Auto", "Unknown", "Enrolled", "NotEnrolled")]
        [string]$UserDeclaredEsuStatus = "Auto"
    )

    $caption = [string]$SystemInventory.OSName
    $build = 0
    [void][int]::TryParse([string]$SystemInventory.BuildNumber, [ref]$build)
    $productType = $SystemInventory.ProductType
    $isServer = ($productType -and [int]$productType -ne 1)
    $esuDetected = [bool]($EsuLines -and $EsuLines.Count -gt 0)
    $isWindows10 = ($caption -match "Windows 10")
    $windows10BuildEligibleForConsumerEsu = ($isWindows10 -and $build -ge 19045)
    $postEosCutoff = [datetime]"2025-10-14"
    $postEosHotfixes = @()
    foreach ($hotfix in @($RecentHotfixes)) {
        try {
            if ($null -ne $hotfix.InstalledOn -and [string]$hotfix.HotFixID -match '^KB') {
                $installed = [datetime]$hotfix.InstalledOn
                if ($installed -gt $postEosCutoff) { $postEosHotfixes += $hotfix }
            }
        }
        catch { }
    }
    $postEosUpdateSignal = ($postEosHotfixes.Count -gt 0)
    $postEosUpdateEvidence = if ($postEosUpdateSignal) {
        $latestPostEos = @($postEosHotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1)[0]
        "$($postEosHotfixes.Count) KB update(s) installed after Windows 10 end of support; newest=$($latestPostEos.HotFixID) on $($latestPostEos.InstalledOn)"
    }
    else {
        "No post-end-of-support KB update evidence was found by Get-HotFix."
    }

    $status = "Unknown"
    $detail = "Windows support posture could not be determined from local inventory."
    $recommendation = "Confirm the Windows version, servicing status, and update eligibility before relying on automatic Secure Boot certificate refresh behavior."
    $servicingPathSummary = "Unknown"

    if ($isServer) {
        $status = "ServerOrSpecialized"
        $servicingPathSummary = "Server or specialized Windows path"
        $detail = "This appears to be a Windows Server or specialized Windows installation. Secure Boot certificate refresh behavior may differ from consumer/business desktop Windows."
        $recommendation = "Validate against the applicable Microsoft/OEM/server vendor servicing guidance before changing firmware or Secure Boot settings."
    }
    elseif ($caption -match "Windows 11" -or $build -ge 22000) {
        $status = "SupportedDesktop"
        $servicingPathSummary = "Supported Windows desktop path"
        $detail = "This appears to be Windows 11 or newer desktop Windows. Supported systems are the expected path for Windows-delivered Secure Boot certificate updates."
        $recommendation = "Install current Windows cumulative updates, apply OEM firmware updates, reboot, and rerun this advisor."
    }
    elseif ($isWindows10) {
        $buildNote = if ($windows10BuildEligibleForConsumerEsu) { "The local build appears consistent with Windows 10 version 22H2, which is a prerequisite for the consumer ESU program." } else { "The local build was not recognized as Windows 10 version 22H2. Consumer ESU eligibility should be checked in Settings. Build=$build." }

        if ($UserDeclaredEsuStatus -eq "Enrolled") {
            $status = "Windows10EsuUserConfirmed"
            $servicingPathSummary = "Windows 10 ESU user-confirmed"
            $supportingEvidenceNote = "No additional local ESU supporting evidence was detected by this run."
            if ($esuDetected -and $postEosUpdateSignal) {
                $supportingEvidenceNote = "Local supporting evidence was also detected: possible ESU-related licensing text and post-end-of-support KB update evidence. $postEosUpdateEvidence"
            }
            elseif ($esuDetected) {
                $supportingEvidenceNote = "Local supporting evidence was also detected: possible ESU-related licensing text."
            }
            elseif ($postEosUpdateSignal) {
                $supportingEvidenceNote = "Local supporting evidence was also detected: post-end-of-support KB update evidence. $postEosUpdateEvidence"
            }
            $detail = "This appears to be Windows 10. ESU enrollment was user-confirmed using the Windows10EsuStatus parameter. $supportingEvidenceNote Consumer ESU enrollment should still be verified in Windows Update settings because this tool cannot independently prove enrollment. $buildNote"
            $recommendation = "Keep ESU enrollment active, verify enrollment in Settings > Update & Security > Windows Update, apply Windows and OEM firmware updates, reboot, and rerun this advisor."
        }
        elseif ($UserDeclaredEsuStatus -eq "NotEnrolled") {
            $status = "Windows10NoEsuUserReported"
            $servicingPathSummary = "Windows 10 ESU not enrolled per user input"
            $detail = "This appears to be Windows 10 and the user indicated this device is not enrolled in ESU. Windows 10 devices without ESU are not on a supported post-end-of-support Windows servicing path. $buildNote"
            $recommendation = "Enroll in Windows 10 ESU if eligible, upgrade to Windows 11 if supported, or treat this device as security-degraded after the certificate transition."
        }
        elseif ($esuDetected) {
            $status = "Windows10EsuSignalDetected"
            $servicingPathSummary = "Windows 10 ESU local licensing text signal detected"
            $detail = "This appears to be Windows 10 and possible ESU-related licensing text was detected. This is a signal, not proof of update eligibility. $buildNote"
            $recommendation = "Verify ESU enrollment in Settings > Update & Security > Windows Update, then apply Windows and OEM firmware updates before rerunning this advisor."
        }
        elseif ($UserDeclaredEsuStatus -eq "Auto" -and $postEosUpdateSignal) {
            $status = "Windows10PostEosUpdateEvidenceDetected"
            $servicingPathSummary = "Windows 10 post-EOS update evidence detected"
            $detail = "This appears to be Windows 10 and local update history shows one or more KB updates installed after Windows 10 end of support. This is useful local evidence that the device may be receiving post-EOS servicing, but it is not independent proof of consumer ESU enrollment. $buildNote $postEosUpdateEvidence"
            $recommendation = "Verify ESU enrollment in Settings > Update & Security > Windows Update, keep Windows/OEM firmware current, and rerun this advisor after monthly updates."
        }
        elseif ($LicenseDetailsCollected) {
            $status = "Windows10EsuNotConfirmed"
            $servicingPathSummary = "Windows 10 ESU not confirmed by local licensing text"
            $detail = "This appears to be Windows 10. License details were collected, but this tool did not find an ESU text signal. That is not definitive proof that ESU is absent, especially for consumer ESU enrollment. $buildNote"
            $recommendation = "Check Settings > Update & Security > Windows Update for ESU enrollment status, or rerun with -Windows10EsuStatus Enrolled if you have already confirmed enrollment in Windows Settings."
        }
        elseif ($UserDeclaredEsuStatus -eq "Auto") {
            $status = "Windows10EsuNotConfirmed"
            $servicingPathSummary = "Windows 10 ESU not locally verified"
            $detail = "This appears to be Windows 10. The default Auto check did not find local ESU evidence from the available non-sensitive signals. This is not proof that ESU is absent. $buildNote $postEosUpdateEvidence"
            $recommendation = "Check Settings > Update & Security > Windows Update for ESU enrollment status. If enrolled, rerun with -Windows10EsuStatus Enrolled to include that user-confirmed context."
        }
        else {
            $status = "Windows10EsuNotChecked"
            $servicingPathSummary = "Windows 10 ESU not checked"
            $detail = "This appears to be Windows 10. ESU status was not checked because no local signal was requested or supplied. $buildNote"
            $recommendation = "Verify ESU enrollment in Settings > Update & Security > Windows Update, or rerun with -IncludeLicenseDetails and/or -Windows10EsuStatus Enrolled if applicable."
        }
    }
    elseif ($caption) {
        $status = "PossiblyUnsupported"
        $servicingPathSummary = "Possibly unsupported Windows path"
        $detail = "This appears to be an older or non-standard Windows version: $caption."
        $recommendation = "Move to a supported Windows release or validate a vendor-supported path for Secure Boot certificate refresh."
    }

    (New-AdvisorObject -Properties ([ordered]@{
        Status                               = $status
        Detail                               = (Protect-String -Value $detail)
        Recommendation                       = (Protect-String -Value $recommendation)
        ServicingPathSummary                 = $servicingPathSummary
        EsuSignal                            = $esuDetected
        PostEosUpdateSignal                  = $postEosUpdateSignal
        PostEosUpdateEvidence                = (Protect-String -Value $postEosUpdateEvidence)
        UserDeclaredEsuStatus                = $UserDeclaredEsuStatus
        LicenseDetailsCollected              = $LicenseDetailsCollected
        Windows10BuildEligibleForConsumerEsu = $windows10BuildEligibleForConsumerEsu
        BuildNumber                          = $build
    }))
}


# -----------------------------------------------------------------------------
# Function: Get-CertificateRefreshContext
# Purpose : Explains certificate refresh eligibility, local rollout evidence, timing interpretation, and admin purpose.
# Safety  : Advisor context only.
# -----------------------------------------------------------------------------

function Get-CertificateRefreshContext {
    param(
        [Parameter(Mandatory = $true)][object]$SystemInventory,
        [Parameter(Mandatory = $true)][object]$Firmware,
        [Parameter(Mandatory = $true)][object]$SecureBoot,
        [Parameter(Mandatory = $true)][object]$UefiVariables,
        [Parameter(Mandatory = $true)][object]$WindowsSupport
    )

    $eligiblePath = "Unknown"
    $eligibilitySummary = "Certificate update eligibility could not be determined from local evidence."
    $adminPreparationSummary = "Use this advisor to separate device prerequisites, servicing eligibility, update rollout state, and safe next actions."
    $deploymentState = "NotConfirmed"
    $deploymentSummary = "The newer Secure Boot certificate signal was not confirmed locally."
    $deadlineMeaning = "This is not a device shutdown deadline. Devices without newer certificates are expected to continue booting, but Microsoft says they can enter a degraded boot-security state and may miss future boot-level protections."
    $expectedTiming = "Microsoft says the certificate refresh is already rolling out through regular monthly Windows updates in a careful, phased deployment. There is no guaranteed per-device installation date exposed by this tool."
    $consumerCheck = "For personal Windows 10 devices, verify ESU enrollment in Settings > Update & Security > Windows Update. For Windows 11 or Windows 10 ESU devices, install current monthly Windows updates, apply OEM firmware updates, reboot, and rerun."
    $organizationCheck = "For organizations, validate update rings, diagnostic data/readiness signals, OEM firmware, BitLocker recovery-key escrow, and any Microsoft/OEM deployment playbook steps before broad remediation."
    $confidence = "Medium"

    if ($Firmware.FirmwareType -eq "BIOS") {
        $eligiblePath = "NotEligibleLegacyBios"
        $eligibilitySummary = "This device is booted in legacy BIOS mode, so normal Secure Boot certificate update readiness does not apply until UEFI boot is used."
        $confidence = "High"
    }
    elseif ($SecureBoot.Enabled -eq $false) {
        $eligiblePath = "SecureBootDisabled"
        $eligibilitySummary = "The device is UEFI-capable but Secure Boot is disabled. Certificate readiness should be reviewed after Secure Boot is enabled safely."
        $confidence = "High"
    }
    elseif ($WindowsSupport.Status -eq "SupportedDesktop") {
        $eligiblePath = "EligibleSupportedWindows"
        $eligibilitySummary = "This device appears to be on a supported Windows desktop servicing path. It is expected to receive the certificate refresh through regular Windows updates if targeting/readiness requirements are met."
    }
    elseif ($WindowsSupport.Status -eq "Windows10EsuUserConfirmed") {
        $eligiblePath = "EligibleWindows10EsuUserConfirmed"
        $eligibilitySummary = "This device appears to be Windows 10 and ESU enrollment was user-confirmed. It should be considered potentially eligible for the Windows-delivered certificate refresh, but enrollment should still be verified in Windows Update settings."
    }
    elseif ($WindowsSupport.Status -eq "Windows10EsuSignalDetected") {
        $eligiblePath = "EligibleWindows10EsuSignalDetected"
        $eligibilitySummary = "This device appears to be Windows 10 and a local ESU-related licensing text signal was detected. Treat it as potentially eligible, then verify ESU enrollment in Windows Update settings."
    }
    elseif ($WindowsSupport.Status -eq "Windows10PostEosUpdateEvidenceDetected") {
        $eligiblePath = "EligibleWindows10PostEosUpdateEvidenceDetected"
        $eligibilitySummary = "This device appears to be Windows 10 and local update history shows post-end-of-support KB update evidence. Treat it as potentially eligible, then verify ESU enrollment in Windows Update settings."
    }
    elseif ($WindowsSupport.Status -eq "Windows10EsuNotChecked" -or $WindowsSupport.Status -eq "Windows10EsuNotConfirmed") {
        $eligiblePath = "PotentiallyEligibleWindows10EsuVerificationNeeded"
        $eligibilitySummary = "This device appears to be Windows 10 22H2 or similar. It may be eligible for the certificate refresh if ESU is enrolled, but ESU enrollment was not verified by this run."
    }
    elseif ($WindowsSupport.Status -eq "Windows10NoEsuUserReported") {
        $eligiblePath = "NotEligibleWindows10NoEsuReported"
        $eligibilitySummary = "This device appears to be Windows 10 and the user reported that ESU is not enrolled. Microsoft says unsupported Windows 10 devices without ESU do not receive Windows updates and will not receive the new certificates."
        $confidence = "Medium"
    }
    elseif ($WindowsSupport.Status -eq "ServerOrSpecialized") {
        $eligiblePath = "SpecializedPath"
        $eligibilitySummary = "This appears to be a server or specialized Windows installation. Update handling may differ and should be validated against Microsoft/OEM/server guidance."
    }
    elseif ($WindowsSupport.Status -eq "PossiblyUnsupported") {
        $eligiblePath = "NotConfirmedPossiblyUnsupported"
        $eligibilitySummary = "This device does not appear to be on a clearly supported desktop servicing path. Validate OS support and vendor guidance."
    }

    if ($UefiVariables.Detected2023Pattern) {
        $deploymentState = "Detected"
        $deploymentSummary = "A simple local text scan detected a known 2023 Secure Boot certificate string in readable UEFI variable data."
        $confidence = "Medium"
    }
    elseif ($UefiVariables.ReadableCount -gt 0) {
        $deploymentState = "NotConfirmedReadableUefiData"
        $deploymentSummary = "UEFI variables were readable, but the simple text scan did not confirm a 2023 certificate string. This can mean the update has not landed yet, the data is binary/non-text, the device is blocked by rollout targeting, or OEM firmware is needed."
    }
    else {
        $deploymentState = "UnknownUefiDataNotReadable"
        $deploymentSummary = "UEFI variable data was not readable by this run, so local certificate signal detection is inconclusive."
        $confidence = "Low"
    }

    $now = Get-Date
    $phase = "BeforeLateJune2026"
    if ($now -ge [datetime]"2026-06-24") {
        $phase = "LateJune2026OrLater"
    }
    if ($now -ge [datetime]"2026-10-01") {
        $phase = "October2026OrLater"
    }

    $phaseSummary = switch ($phase) {
        "BeforeLateJune2026" { "The original certificates begin expiring in late June 2026. Before that window, absence of a local 2023 signal should be treated as a readiness/review item, not proof of failure." }
        "LateJune2026OrLater" { "The late-June 2026 expiration window has started or passed. Devices without confirmed newer certificates should be reviewed more urgently, although Microsoft says devices continue to boot and standard Windows updates continue to install." }
        "October2026OrLater" { "The broader 2026 certificate expiration period is in progress or largely elapsed. Treat unconfirmed certificate state as a higher-priority review item, especially for unsupported or unmanaged devices." }
        default { "Certificate transition phase could not be categorized." }
    }

    (New-AdvisorObject -Properties ([ordered]@{
        EligiblePath               = $eligiblePath
        EligibilitySummary         = (Protect-String -Value $eligibilitySummary)
        DeploymentState            = $deploymentState
        DeploymentSummary          = (Protect-String -Value $deploymentSummary)
        ExpectedTiming             = $expectedTiming
        DeadlineMeaning            = $deadlineMeaning
        TransitionPhase            = $phase
        TransitionPhaseSummary     = $phaseSummary
        ConsumerCheck              = $consumerCheck
        OrganizationCheck          = $organizationCheck
        AdminPreparationSummary    = $adminPreparationSummary
        Confidence                 = $confidence
    }))
}

# -----------------------------------------------------------------------------
# Function: Invoke-LicenseSignalCollection
# Purpose : Optionally captures slmgr /dlv output to a separate local file and extracts possible ESU-related lines.
# Safety  : Read-only, but output may contain environment-specific licensing identifiers.
# -----------------------------------------------------------------------------

function Invoke-LicenseSignalCollection {
    param([string]$Path)

    $esuLines = @()
    $errorText = $null

    try {
        cmd.exe /c "cscript.exe //NoLogo $env:windir\system32\slmgr.vbs /dlv" | Out-File -LiteralPath $Path -Encoding UTF8 -Force
        $text = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
        $esuLines = @($text | Where-Object { $_ -match "ESU|Extended Security Updates|Extended Security Update" } | ForEach-Object { Protect-String -Value $_ })
    }
    catch {
        $errorText = $_.Exception.Message
    }

    (New-AdvisorObject -Properties ([ordered]@{
        Collected = [bool](Test-Path -LiteralPath $Path)
        Path      = (Protect-String -Value $Path)
        EsuLines  = @($esuLines)
        Error     = (Protect-String -Value $errorText)
    }))
}

#endregion Windows support and certificate-refresh context

#region Advisor rules and assessment
# Purpose: turn collected evidence into deterministic status, risk, confidence, findings, and approved next actions.
# -----------------------------------------------------------------------------
# Function: Invoke-AdvisorRules
# Purpose : Applies deterministic rules to produce findings from the collected audit evidence.
# Safety  : No remediation. Findings only.
# -----------------------------------------------------------------------------

function Invoke-AdvisorRules {
    param(
        [Parameter(Mandatory = $true)][object]$Audit
    )

    if (-not $Audit.IsAdministrator) {
        Add-Finding -Severity "Medium" -Category "Permissions" -Title "Run elevated for highest-confidence results" -Detail "The advisor is not running with administrative rights. Some Secure Boot, BitLocker, TPM, event log, and EFI checks may be incomplete." -Recommendation "Rerun PowerShell as Administrator before making remediation decisions." -Evidence "IsAdministrator=False"
    }

    if ($Audit.Firmware.FirmwareType -eq "BIOS") {
        Add-Finding -Severity "High" -Category "Firmware" -Title "System is booted in legacy BIOS mode" -Detail "Secure Boot requires UEFI. A system booted in legacy BIOS mode cannot use normal Secure Boot protections." -Recommendation "Back up the system, confirm disk layout and recovery readiness, evaluate MBR2GPT only if appropriate, switch firmware to UEFI mode, enable Secure Boot, then rerun this advisor." -Evidence "FirmwareType=$($Audit.Firmware.FirmwareType); DetectionMethod=$($Audit.Firmware.DetectionMethod); Confidence=$($Audit.Firmware.Confidence); RawValue=$($Audit.Firmware.RawValue)"
    }
    elseif ($Audit.Firmware.FirmwareType -eq "UEFI") {
        Add-Finding -Severity "Info" -Category "Firmware" -Title "System is booted in UEFI mode" -Detail "The device reports UEFI firmware mode, which is required for Secure Boot." -Recommendation "Continue evaluating Secure Boot state, BitLocker readiness, firmware currency, and certificate signals." -Evidence "FirmwareType=$($Audit.Firmware.FirmwareType); DetectionMethod=$($Audit.Firmware.DetectionMethod); Confidence=$($Audit.Firmware.Confidence); RawValue=$($Audit.Firmware.RawValue)"
    }
    else {
        Add-Finding -Severity "Medium" -Category "Firmware" -Title "Firmware mode could not be confirmed" -Detail "The advisor could not confidently determine whether this device is booted using UEFI or legacy BIOS." -Recommendation "Rerun elevated and confirm firmware mode using System Information or firmware setup." -Evidence $Audit.Firmware.Error
    }

    if ($Audit.SecureBoot.Enabled -eq $true) {
        Add-Finding -Severity "Info" -Category "Secure Boot" -Title "Secure Boot is enabled" -Detail "Confirm-SecureBootUEFI returned True." -Recommendation "Continue validating certificate signals and firmware/update readiness." -Evidence "Confirm-SecureBootUEFI=True"
    }
    elseif ($Audit.SecureBoot.Enabled -eq $false) {
        Add-Finding -Severity "Medium" -Category "Secure Boot" -Title "Secure Boot is disabled" -Detail "The device appears to support Secure Boot checks, but Secure Boot is currently disabled." -Recommendation "Confirm BitLocker recovery key backup first. Then enable Secure Boot in firmware setup, reboot, and rerun this advisor." -Evidence "Confirm-SecureBootUEFI=False"
    }
    else {
        Add-Finding -Severity "Medium" -Category "Secure Boot" -Title "Secure Boot state is unknown" -Detail "Secure Boot state could not be confirmed from PowerShell." -Recommendation "Rerun elevated on a supported Windows version. If the device is legacy BIOS, Secure Boot will not be available until converted to UEFI boot mode." -Evidence $Audit.SecureBoot.Error
    }

    if ($Audit.BootManager.BootFilePath -and $Audit.BootManager.SignatureStatus -eq "Valid") {
        Add-Finding -Severity "Info" -Category "Boot Integrity" -Title "Windows boot manager signature is valid" -Detail "The discovered boot manager file has a valid Authenticode signature." -Recommendation "No boot manager signature remediation is indicated by this check." -Evidence "Signer=$($Audit.BootManager.SignerSubject); NotAfter=$($Audit.BootManager.SignerNotAfter)"
    }
    elseif ($Audit.BootManager.BootFilePath -and $Audit.BootManager.SignatureStatus) {
        Add-Finding -Severity "Critical" -Category "Boot Integrity" -Title "Windows boot manager signature is not valid" -Detail "The discovered boot manager file did not return a Valid Authenticode signature." -Recommendation "Treat this as a possible integrity issue. Do not perform Secure Boot certificate remediation first. Run offline malware scanning, validate boot configuration, run SFC/DISM, and escalate to incident response if unexpected." -Evidence "Status=$($Audit.BootManager.SignatureStatus); Message=$($Audit.BootManager.SignatureMessage)"
    }
    else {
        Add-Finding -Severity "Medium" -Category "Boot Integrity" -Title "Windows boot manager was not validated" -Detail "The advisor could not locate or validate bootmgfw.efi using standard paths." -Recommendation "Rerun elevated. If ESP mounting was skipped or blocked by drive-letter collision, rerun with an available ESP drive letter or inspect the EFI System Partition manually." -Evidence "MountSkipped=$($Audit.BootManager.MountSkippedReason); MountError=$($Audit.BootManager.MountError); SigError=$($Audit.BootManager.SignatureError)"
    }

    if ($Audit.UefiVariables.CommandPresent -and ($Audit.UefiVariables.Variables | Where-Object { $_.Readable } | Select-Object -First 1)) {
        if ($Audit.UefiVariables.Detected2023Pattern) {
            Add-Finding -Severity "Info" -Category "Certificates" -Title "2023 Secure Boot certificate text signal detected" -Detail "A simple text scan of readable Secure Boot UEFI variables found a 2023 Microsoft certificate string. This is a useful signal, not a complete certificate parser." -Recommendation "Keep Windows and OEM firmware current, then rerun after major updates." -Evidence (($Audit.UefiVariables.Variables | ForEach-Object { "$($_.Name): $($_.TextMatches -join ', ')" }) -join "; ")
        }
        elseif ($Audit.UefiVariables.Detected2011Pattern) {
            Add-Finding -Severity "Medium" -Category "Certificates" -Title "Only older 2011 certificate text signal detected" -Detail "Readable Secure Boot variables showed an older 2011 Microsoft certificate string, but this tool did not detect a 2023 certificate string by simple text scan." -Recommendation "Install current Windows updates, apply the latest OEM firmware, reboot, and rerun. If still unchanged, review Microsoft/OEM Secure Boot certificate deployment guidance." -Evidence (($Audit.UefiVariables.Variables | ForEach-Object { "$($_.Name): $($_.TextMatches -join ', ')" }) -join "; ")
        }
        else {
            Add-Finding -Severity "Low" -Category "Certificates" -Title "2023 certificate text signal was not detected by simple scan" -Detail "UEFI variables were readable, but this tool did not detect known 2023 Microsoft certificate strings by simple text scan. This is not proof that the certificates are absent because UEFI signature data is binary and certificate deployment is phased." -Recommendation "Use this as a review signal, not a failure. Install Windows updates, apply OEM firmware, reboot, and rerun. Escalate to Microsoft/OEM guidance if the device remains unclear after updates." -Evidence "UEFI variables readable, no known 2023 text match from simple scan."
        }
    }
    else {
        Add-Finding -Severity "Medium" -Category "Certificates" -Title "Secure Boot UEFI variables were not readable" -Detail "The advisor could not read Secure Boot UEFI variables using Get-SecureBootUEFI." -Recommendation "Rerun elevated on UEFI Windows. If unavailable, rely on Windows update state, OEM firmware guidance, and firmware setup information." -Evidence $Audit.UefiVariables.Error
    }

    if ($Audit.SecureBootRegistry.Readable) {
        if ($Audit.SecureBootRegistry.Specific.UEFICA2023Status) {
            Add-Finding -Severity "Info" -Category "Windows Update Signals" -Title "UEFICA2023Status registry value is present" -Detail "Windows exposes a UEFICA2023Status value under the SecureBoot registry key." -Recommendation "Use this as a Windows servicing signal alongside UEFI variable checks and OEM guidance. Rerun after Windows and firmware updates." -Evidence "UEFICA2023Status=$($Audit.SecureBootRegistry.Specific.UEFICA2023Status); AvailableUpdates=$($Audit.SecureBootRegistry.Specific.AvailableUpdates)"
        }
        else {
            Add-Finding -Severity "Low" -Category "Windows Update Signals" -Title "UEFICA2023Status registry value was not found" -Detail "The SecureBoot registry key was readable, but UEFICA2023Status was not present." -Recommendation "This may be normal depending on Windows build and update state. Install current cumulative updates and rerun." -Evidence "SecureBoot registry readable."
        }
    }
    else {
        Add-Finding -Severity "Low" -Category "Windows Update Signals" -Title "SecureBoot registry key was not readable" -Detail "The advisor could not read the SecureBoot registry key." -Recommendation "Rerun elevated and confirm the system is using UEFI firmware." -Evidence $Audit.SecureBootRegistry.Error
    }

    if ($Audit.System.BIOSAgeDays -and [int]$Audit.System.BIOSAgeDays -gt 730) {
        Add-Finding -Severity "Low" -Category "Firmware" -Title "Firmware appears older than 24 months" -Detail "The BIOS/UEFI release date appears to be more than two years old. Firmware age is not proof of a problem, but it is a useful maintenance signal." -Recommendation "Check the OEM support site for BIOS/UEFI firmware updates before assuming Windows Update alone can complete Secure Boot certificate maintenance." -Evidence "BIOSReleaseDate=$($Audit.System.BIOSReleaseDate); BIOSAgeDays=$($Audit.System.BIOSAgeDays)"
    }

    if ($Audit.BitLocker.CommandPresent) {
        $protectedVolumes = @($Audit.BitLocker.Volumes | Where-Object {
            $protectionStatus = [string]$_.ProtectionStatus
            $volumeStatus = [string]$_.VolumeStatus
            $encryptionPct = 0
            try { if ($_.EncryptionPercentage -ne $null) { $encryptionPct = [int]$_.EncryptionPercentage } } catch { $encryptionPct = 0 }

            ($protectionStatus -match "^(On|1|Protected)$") -or
            ($volumeStatus -match "EncryptionInProgress|FullyEncrypted|EncryptionPaused|DecryptionPaused|UsedSpaceOnlyEncrypted") -or
            ($encryptionPct -gt 0)
        })
        foreach ($volume in $protectedVolumes) {
            Add-Finding -Severity "Medium" -Category "BitLocker" -Title "BitLocker protection is enabled" -Detail "BitLocker appears enabled on $($volume.MountPoint). Firmware, Secure Boot, DBX, and boot manager changes can trigger recovery prompts on some systems." -Recommendation "Confirm recovery key escrow or backup before applying firmware or Secure Boot remediation. In managed environments, verify Entra ID, Active Directory, MBAM, or endpoint management escrow." -Evidence "MountPoint=$($volume.MountPoint); ProtectionStatus=$($volume.ProtectionStatus); Protectors=$($volume.KeyProtectorTypes)"
            if (-not $volume.RecoveryPasswordProtectorFound) {
                Add-Finding -Severity "High" -Category "BitLocker" -Title "No recovery password protector was detected locally" -Detail "The local BitLocker metadata did not show a RecoveryPassword protector for $($volume.MountPoint). This does not prove no recovery key exists, but it raises the stakes before firmware or Secure Boot work." -Recommendation "Do not make firmware or Secure Boot changes until recovery key availability is confirmed through the organization's escrow system or local backup records." -Evidence "MountPoint=$($volume.MountPoint); Protectors=$($volume.KeyProtectorTypes)"
            }
        }
    }
    else {
        Add-Finding -Severity "Low" -Category "BitLocker" -Title "BitLocker status could not be collected" -Detail "The BitLocker PowerShell cmdlet was not available." -Recommendation "Manually confirm BitLocker state and recovery key backup before firmware or Secure Boot remediation." -Evidence $Audit.BitLocker.Error
    }

    if ($Audit.Tpm.CommandPresent -and $Audit.Tpm.TpmPresent -eq $true) {
        if ($Audit.Tpm.TpmReady -eq $true -and $Audit.Tpm.TpmEnabled -eq $true) {
            Add-Finding -Severity "Info" -Category "TPM" -Title "TPM is present and ready" -Detail "The TPM appears present, enabled, and ready." -Recommendation "No TPM-specific remediation is indicated by this check." -Evidence "TPMReady=$($Audit.Tpm.TpmReady); TPMEnabled=$($Audit.Tpm.TpmEnabled); TPMOwned=$($Audit.Tpm.TpmOwned)"
        }
        else {
            Add-Finding -Severity "Medium" -Category "TPM" -Title "TPM is present but not fully ready" -Detail "The TPM is present, but one or more readiness indicators are not true." -Recommendation "Review firmware TPM settings and Windows TPM health before making Secure Boot or BitLocker-impacting changes." -Evidence "TPMReady=$($Audit.Tpm.TpmReady); TPMEnabled=$($Audit.Tpm.TpmEnabled); TPMActivated=$($Audit.Tpm.TpmActivated)"
        }
    }
    else {
        Add-Finding -Severity "Low" -Category "TPM" -Title "TPM status is unavailable or TPM is absent" -Detail "The advisor could not confirm a ready TPM." -Recommendation "Confirm TPM state manually if this device uses BitLocker, Windows Hello, Credential Guard, or Windows 11 readiness controls." -Evidence $Audit.Tpm.Error
    }

    if ($Audit.WindowsSupport.Status -eq "SupportedDesktop") {
        Add-Finding -Severity "Info" -Category "Windows Support" -Title "Windows support posture appears favorable" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); ServicingPath=$($Audit.WindowsSupport.ServicingPathSummary)"
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10EsuUserConfirmed") {
        Add-Finding -Severity "Low" -Category "Windows Support" -Title "Windows 10 ESU enrollment was user-confirmed" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); UserDeclaredEsuStatus=$($Audit.WindowsSupport.UserDeclaredEsuStatus); EsuTextSignal=$($Audit.WindowsSupport.EsuSignal); PostEosUpdateSignal=$($Audit.WindowsSupport.PostEosUpdateSignal); Windows10BuildEligibleForConsumerEsu=$($Audit.WindowsSupport.Windows10BuildEligibleForConsumerEsu)"
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10EsuSignalDetected") {
        Add-Finding -Severity "Low" -Category "Windows Support" -Title "Windows 10 ESU local signal detected" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); Windows10BuildEligibleForConsumerEsu=$($Audit.WindowsSupport.Windows10BuildEligibleForConsumerEsu)"
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10EsuNotChecked" -or $Audit.WindowsSupport.Status -eq "Windows10EsuNotConfirmed") {
        Add-Finding -Severity "Medium" -Category "Windows Support" -Title "Windows 10 ESU verification recommended" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); UserDeclaredEsuStatus=$($Audit.WindowsSupport.UserDeclaredEsuStatus); LicenseDetailsCollected=$($Audit.WindowsSupport.LicenseDetailsCollected); Windows10BuildEligibleForConsumerEsu=$($Audit.WindowsSupport.Windows10BuildEligibleForConsumerEsu)"
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10NoEsuUserReported") {
        Add-Finding -Severity "High" -Category "Windows Support" -Title "Windows 10 ESU is not enrolled per user input" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); UserDeclaredEsuStatus=$($Audit.WindowsSupport.UserDeclaredEsuStatus); Windows10BuildEligibleForConsumerEsu=$($Audit.WindowsSupport.Windows10BuildEligibleForConsumerEsu)"
    }
    elseif ($Audit.WindowsSupport.Status -eq "PossiblyUnsupported") {
        Add-Finding -Severity "High" -Category "Windows Support" -Title "Supported update path is not confirmed" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); ServicingPath=$($Audit.WindowsSupport.ServicingPathSummary)"
    }
    else {
        Add-Finding -Severity "Medium" -Category "Windows Support" -Title "Specialized or unknown Windows support posture" -Detail $Audit.WindowsSupport.Detail -Recommendation $Audit.WindowsSupport.Recommendation -Evidence "Status=$($Audit.WindowsSupport.Status); ServicingPath=$($Audit.WindowsSupport.ServicingPathSummary)"
    }

    if ($Audit.CertificateRefresh.DeploymentState -eq "Detected") {
        Add-Finding -Severity "Info" -Category "Certificate Rollout" -Title "2023 Secure Boot certificate signal detected" -Detail $Audit.CertificateRefresh.DeploymentSummary -Recommendation "No certificate-specific action is indicated by this local signal. Continue applying normal Windows and OEM firmware updates." -Evidence "DeploymentState=$($Audit.CertificateRefresh.DeploymentState); EligiblePath=$($Audit.CertificateRefresh.EligiblePath)"
    }
    elseif ($Audit.CertificateRefresh.EligiblePath -match "NotEligible|SecureBootDisabled|LegacyBios") {
        Add-Finding -Severity "Medium" -Category "Certificate Rollout" -Title "Certificate refresh eligibility is blocked or not applicable" -Detail $Audit.CertificateRefresh.EligibilitySummary -Recommendation $Audit.CertificateRefresh.ConsumerCheck -Evidence "EligiblePath=$($Audit.CertificateRefresh.EligiblePath); DeploymentState=$($Audit.CertificateRefresh.DeploymentState)"
    }
    else {
        Add-Finding -Severity "Low" -Category "Certificate Rollout" -Title "Certificate rollout has not been locally confirmed" -Detail $Audit.CertificateRefresh.DeploymentSummary -Recommendation "Treat this as a rollout/readiness review item. Apply current monthly Windows updates, apply OEM firmware updates, reboot, then rerun. In managed environments, review Microsoft/OEM playbook guidance and rollout targeting requirements." -Evidence "EligiblePath=$($Audit.CertificateRefresh.EligiblePath); DeploymentState=$($Audit.CertificateRefresh.DeploymentState); TransitionPhase=$($Audit.CertificateRefresh.TransitionPhase)"
    }

    if ($Audit.RelevantEvents -and $Audit.RelevantEvents.Count -gt 0) {
        Add-Finding -Severity "Medium" -Category "Event Logs" -Title "Recent relevant warnings/errors were found" -Detail "The advisor found recent warnings/errors mentioning Secure Boot, BitLocker, TPM, UEFI, firmware, boot manager, PCR7, or recovery keys." -Recommendation "Review the event table before remediation, especially if BitLocker recovery, TPM, or boot issues are mentioned." -Evidence "RelevantEventCount=$($Audit.RelevantEvents.Count)"
    }
}

# -----------------------------------------------------------------------------
# Function: Get-OverallAssessment
# Purpose : Calculates overall status, risk, confidence, headline, and next action from findings and support/certificate context.
# Safety  : Deterministic assessment only.
# -----------------------------------------------------------------------------

function Get-OverallAssessment {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $findings = @($script:Findings)
    $maxRank = 0
    if ($findings.Count -gt 0) {
        $maxRank = ($findings | Measure-Object -Property SeverityRank -Maximum).Maximum
    }

    $status = "Unknown"
    $risk = "Unknown"
    $confidence = "Medium"
    $headline = "Review recommended"
    $nextAction = "Review the findings and apply the safest remediation path for this device."

    if ($Audit.Firmware.FirmwareType -eq "BIOS") {
        $status = "Unsupported"
        $risk = "High"
        $confidence = "High"
        $headline = "Legacy BIOS boot mode blocks Secure Boot."
        $nextAction = "Evaluate UEFI conversion only after backup and recovery planning."
    }
    elseif ($maxRank -ge 5) {
        $status = "PossibleIntegrityIssue"
        $risk = "Critical"
        $confidence = "High"
        $headline = "Possible boot integrity issue detected."
        $nextAction = "Do not start certificate remediation. Validate boot integrity and escalate if unexpected."
    }
    elseif (-not $Audit.IsAdministrator) {
        $status = "InsufficientPermissions"
        $risk = "Unknown"
        $confidence = "Low"
        $headline = "Rerun elevated for a complete assessment."
        $nextAction = "Open PowerShell as Administrator and rerun this advisor."
    }
    elseif ($Audit.SecureBoot.Enabled -eq $false) {
        $status = "ActionRequired"
        $risk = "Medium"
        $confidence = "High"
        $headline = "Secure Boot is disabled."
        $nextAction = "Confirm BitLocker recovery key backup, enable Secure Boot in firmware, reboot, and rerun."
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10NoEsuUserReported") {
        $status = "ActionRequired"
        $risk = "High"
        $confidence = "Medium"
        $headline = "Windows 10 ESU is not enrolled per user input."
        $nextAction = "Enroll in Windows 10 ESU if eligible, upgrade to Windows 11 if supported, or treat this device as security-degraded after the certificate transition."
    }
    elseif ($Audit.WindowsSupport.Status -eq "Windows10EsuNotChecked" -or $Audit.WindowsSupport.Status -eq "Windows10EsuNotConfirmed") {
        $status = "ReviewRecommended"
        $risk = "Medium"
        $confidence = "Medium"
        $headline = "Windows 10 ESU eligibility/enrollment should be confirmed; Secure Boot basics may still be healthy."
        $nextAction = "Check ESU enrollment in Windows Update settings. If enrolled, apply monthly Windows updates and OEM firmware, reboot, and rerun. This is a readiness review, not proof that the update failed."
    }
    elseif (($Audit.WindowsSupport.Status -eq "Windows10EsuUserConfirmed" -or $Audit.WindowsSupport.Status -eq "Windows10EsuSignalDetected" -or $Audit.WindowsSupport.Status -eq "Windows10PostEosUpdateEvidenceDetected") -and (-not $Audit.UefiVariables.Detected2023Pattern)) {
        $status = "ReviewRecommended"
        $risk = "Medium"
        $confidence = "Medium"
        if ($Audit.WindowsSupport.Status -eq "Windows10PostEosUpdateEvidenceDetected") {
            $headline = "Windows 10 post-EOS update evidence was found; certificate rollout has not been locally confirmed."
            $nextAction = "Verify ESU enrollment in Windows Update settings, keep Windows/OEM firmware current, reboot, and rerun. Microsoft deploys certificates through a phased Windows Update process, so there may not be a single expected installation date."
        }
        else {
            $headline = "Windows 10 ESU path noted; certificate rollout has not been locally confirmed."
            $nextAction = "Keep ESU enrollment active, install monthly Windows updates and OEM firmware, reboot, and rerun. Microsoft deploys the certificates through a phased Windows Update process, so there may not be a single expected installation date."
        }
    }
    elseif ($Audit.WindowsSupport.Status -eq "PossiblyUnsupported") {
        $status = "ActionRequired"
        $risk = "High"
        $confidence = "Medium"
        $headline = "Supported update path is not confirmed."
        $nextAction = "Upgrade to a supported Windows release, confirm vendor support, or treat this system as security-degraded."
    }
    elseif (-not $Audit.UefiVariables.Detected2023Pattern) {
        $status = "ReviewRecommended"
        $risk = "Medium"
        $confidence = "Medium"
        $headline = "Eligible update path may exist, but certificate rollout has not been locally confirmed."
        $nextAction = "Install current monthly Windows updates, update OEM firmware, reboot, and rerun. Absence of a local 2023 text signal is a review item, not proof of update failure."
    }
    elseif ($maxRank -ge 4) {
        $status = "ActionRequired"
        $risk = "High"
        $confidence = "Medium"
        $headline = "One or more high-severity readiness issues require attention."
        $nextAction = "Review high-severity findings before applying Secure Boot or firmware changes."
    }
    elseif ($maxRank -ge 3) {
        $status = "ReviewRecommended"
        $risk = "Medium"
        $confidence = "Medium"
        $headline = "Review recommended before remediation."
        $nextAction = "Review findings, especially BitLocker and event log signals, before changing firmware or Secure Boot state."
    }
    else {
        $status = "Ready"
        $risk = "Low"
        $confidence = "Medium"
        $headline = "No major readiness blockers were detected."
        $nextAction = "Keep Windows and OEM firmware current, then rerun after major servicing changes."
    }

    $collectionWarningCount = 0
    if ($Audit.PSObject.Properties.Name -contains "CollectionWarnings") {
        $collectionWarningCount = @($Audit.CollectionWarnings).Count
    }

    $keyEvidenceIncomplete = (
        $Audit.Firmware.FirmwareType -eq "Unknown" -or
        $null -eq $Audit.SecureBoot.Enabled -or
        (-not $Audit.UefiVariables.Detected2023Pattern -and [int]$Audit.UefiVariables.ReadableCount -eq 0)
    )

    if ($keyEvidenceIncomplete -and $confidence -ne "High") {
        $confidence = "Low"
    }
    elseif ($collectionWarningCount -ge 3 -and $confidence -eq "High") {
        $confidence = "Medium"
    }

    (New-AdvisorObject -Properties ([ordered]@{
        Status       = $status
        RiskLevel    = $risk
        Confidence   = $confidence
        Headline     = $headline
        NextAction   = $nextAction
        FindingCount = $findings.Count
        Critical     = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
        High         = @($findings | Where-Object { $_.Severity -eq "High" }).Count
        Medium       = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
        Low          = @($findings | Where-Object { $_.Severity -eq "Low" }).Count
        Info         = @($findings | Where-Object { $_.Severity -eq "Info" }).Count
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-ApprovedRemediationPlaybook
# Purpose : Returns approved remediation guidance text included in reports.
# Safety  : Guidance only, no action.
# -----------------------------------------------------------------------------

function Get-ApprovedRemediationPlaybook {
    return @(
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "Legacy BIOS mode"
            Action = "Back up data, confirm recovery media, verify disk layout, evaluate MBR2GPT only if appropriate, switch firmware to UEFI, enable Secure Boot, and rerun the advisor. Do not do this casually on production systems."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "Secure Boot disabled"
            Action = "Confirm BitLocker recovery key backup, enable Secure Boot in firmware setup, reboot, and rerun the advisor."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "2023 certificate signal missing or unknown"
            Action = "Install current Windows cumulative updates, apply latest OEM BIOS/UEFI firmware, reboot, and rerun. If still unclear, review OEM and Microsoft deployment guidance."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "BitLocker currently enabled"
            Action = "Confirm recovery key escrow or backup before firmware, Secure Boot, DBX, or boot manager changes. In managed environments, verify Entra ID, AD DS, MBAM, or endpoint management escrow."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "BitLocker Secure Boot integrity warning events"
            Action = "Review BitLocker Event ID 815 or related integrity warnings as historical or current firmware/TPM/Secure Boot measurement signals. If BitLocker is currently off, no BitLocker-specific remediation is indicated unless it will be re-enabled. If BitLocker is on or will be re-enabled, confirm recovery key escrow, apply relevant OEM firmware updates, reboot, and rerun the advisor."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "Windows 10 ESU / servicing path review"
            Action = "If ESU is user-confirmed or post-EOS update evidence is present, keep ESU active, verify final enrollment in Windows Update settings, keep Windows/OEM firmware current, and rerun after monthly updates. If ESU is not enrolled, enroll if eligible or upgrade to Windows 11 where possible."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "Linux dual-boot suspected"
            Action = "Update the Linux distribution, shim, GRUB, and firmware first. Confirm the distro supports the newer Secure Boot chain before applying revocation or certificate changes."
        })),
        (New-AdvisorObject -Properties ([ordered]@{
            Scenario = "Boot manager signature invalid"
            Action = "Stop. Do not start Secure Boot certificate remediation. Run offline malware scanning, validate BCD/boot files, run SFC/DISM, and escalate to incident response if unexpected."
        }))
    )
}

# -----------------------------------------------------------------------------
# Function: Get-ShortAdvisorText
# Purpose : Truncates verbose evidence such as event messages for console/text report readability.
# Safety  : Pure formatting helper.
# -----------------------------------------------------------------------------

function Get-ShortAdvisorText {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $false)][int]$MaxLength = 260
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $text = (($Value -replace "`r|`n", " ") -replace "\s+", " ").Trim()
    if ($text.Length -le $MaxLength) { return $text }
    return ($text.Substring(0, $MaxLength) + "...")
}

# -----------------------------------------------------------------------------
# Function: Get-EsuVerificationSummary
# Purpose : Separates user-declared ESU status from local licensing/update evidence.
# Safety  : Interpretation only. Does not change licensing or enrollment.
# -----------------------------------------------------------------------------

function Get-EsuVerificationSummary {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $userAssertion = $Audit.WindowsSupport.UserDeclaredEsuStatus
    $localEvidence = "Not checked"
    $confidence = "Low"

    if ($Audit.WindowsSupport.EsuSignal) {
        $localEvidence = "Possible ESU-related licensing text signal detected"
        $confidence = "Medium"
    }
    elseif ($Audit.WindowsSupport.PostEosUpdateSignal) {
        $localEvidence = "Post-end-of-support KB update evidence detected: $($Audit.WindowsSupport.PostEosUpdateEvidence)"
        $confidence = "Medium"
    }
    elseif ($Audit.WindowsSupport.LicenseDetailsCollected) {
        $localEvidence = "License details checked; ESU text signal not detected"
        $confidence = "Low"
    }

    $note = "Consumer ESU enrollment should be verified in Windows Update settings. A user-declared value is useful context but is not independent proof."

    if ($userAssertion -eq "Enrolled" -and $Audit.WindowsSupport.EsuSignal -and $Audit.WindowsSupport.PostEosUpdateSignal) {
        $confidence = "Medium"
        $note = "Windows 10 ESU was user-confirmed, and local supporting evidence was also detected from licensing text and post-end-of-support update history. Verify final enrollment status in Windows Update settings."
    }
    elseif ($userAssertion -eq "Enrolled" -and $Audit.WindowsSupport.PostEosUpdateSignal) {
        $confidence = "Medium"
        $note = "Windows 10 ESU was user-confirmed, and local post-end-of-support update evidence was also detected. Verify final enrollment status in Windows Update settings."
    }
    elseif ($userAssertion -eq "Enrolled" -and $Audit.WindowsSupport.EsuSignal) {
        $confidence = "Medium"
        $note = "Windows 10 ESU was user-confirmed, and a possible ESU-related licensing text signal was also detected. Verify final enrollment status in Windows Update settings."
    }
    elseif ($userAssertion -eq "Enrolled") {
        $confidence = "Medium"
    }
    elseif ($userAssertion -eq "NotEnrolled") {
        $confidence = "Medium"
        $note = "The operator reported that Windows 10 ESU is not enrolled. Verify in Windows Update settings before treating the device as unsupported."
    }

    return (New-AdvisorObject -Properties ([ordered]@{
        UserAssertion = $userAssertion
        LocalEvidence = $localEvidence
        OverallConfidence = $confidence
        Note = $note
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-CertificateDisplayStatus
# Purpose : Presents certificate rollout detection as a confidence-labeled state instead of a simple true/false.
# Safety  : Interpretation only. Does not parse or modify certificates.
# -----------------------------------------------------------------------------

function Get-CertificateDisplayStatus {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $status = "Not confirmed"
    $confidence = "Low"
    $method = "UEFI variable simple text scan plus Windows registry indicators"
    $reasons = @()

    if ($Audit.UefiVariables.Detected2023Pattern) {
        $status = "Text signal detected"
        $confidence = "Medium"
        $reasons += "A known 2023 Microsoft certificate string appeared in readable UEFI variable data."
    }
    else {
        $reasons += "The Microsoft certificate rollout may not have reached this device yet."
        $reasons += "UEFI signature data is binary and may not expose readable text strings."
        $reasons += "Windows Update targeting/readiness signals may delay deployment."
        $reasons += "OEM BIOS/UEFI firmware may be required before certificate maintenance succeeds."
    }

    if ($Audit.SecureBootRegistry.Specific.UEFICA2023Status) {
        $status = "Windows registry signal present"
        $confidence = "Medium"
    }

    return (New-AdvisorObject -Properties ([ordered]@{
        Status = $status
        Confidence = $confidence
        DetectionMethod = $method
        PossibleReasons = @($reasons)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-DeviceClassification
# Purpose : Gives admins a quick posture classification without overclaiming Windows 11 compatibility.
# Safety  : Interpretation only.
# -----------------------------------------------------------------------------

function Get-DeviceClassification {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $uefiCapable = ($Audit.Firmware.FirmwareType -eq "UEFI")
    $secureBootReady = ($Audit.SecureBoot.Enabled -eq $true)
    $bitLockerCompatible = ($Audit.Tpm.TpmReady -eq $true)
    $certificateReady = if ($Audit.UefiVariables.Detected2023Pattern) { "ConfirmedByTextSignal" } else { "NotLocallyConfirmed" }
    $windows11PrereqSignals = if ($uefiCapable -and $secureBootReady -and $Audit.Tpm.TpmReady) { "Partial prerequisite signals present; CPU, RAM, storage, and official Windows 11 compatibility are not assessed by this tool." } else { "Incomplete prerequisite signals; this tool does not perform full Windows 11 compatibility assessment." }

    return (New-AdvisorObject -Properties ([ordered]@{
        UefiCapable = $uefiCapable
        SecureBootReady = $secureBootReady
        BitLockerCompatibleSignal = $bitLockerCompatible
        CertificateRefreshState = $certificateReady
        Windows11ReadinessNote = $windows11PrereqSignals
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-ReadinessRationale
# Purpose : Produces categorical readiness rationale without a numeric score.
# Safety  : Advisory interpretation only. Not a security guarantee or compliance attestation.
# -----------------------------------------------------------------------------

function Get-ReadinessRationale {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $positiveSignals = @()
    $reviewItems = @()
    $actionItems = @()
    $informationalItems = @()

    if ($Audit.Firmware.FirmwareType -eq "UEFI") {
        $positiveSignals += "UEFI firmware mode detected"
    }
    else {
        $actionItems += "UEFI firmware mode was not confirmed"
    }

    if ($Audit.SecureBoot.Enabled -eq $true) {
        $positiveSignals += "Secure Boot is enabled"
    }
    elseif ($Audit.SecureBoot.Enabled -eq $false) {
        $actionItems += "Secure Boot is disabled"
    }
    else {
        $reviewItems += "Secure Boot state was not confirmed"
    }

    if ($Audit.BootManager.SignatureStatus -eq "Valid") {
        $positiveSignals += "Windows boot manager signature is valid"
    }
    elseif ($Audit.BootManager.SignatureStatus) {
        $actionItems += "Windows boot manager signature is not valid or not confirmed"
    }
    else {
        $reviewItems += "Windows boot manager signature was not confirmed"
    }

    if ($Audit.Tpm.TpmReady -eq $true) {
        $positiveSignals += "TPM is present and ready"
    }
    else {
        $reviewItems += "TPM readiness was not confirmed"
    }

    switch ($Audit.WindowsSupport.Status) {
        "SupportedDesktop" { $positiveSignals += "Supported Windows desktop servicing path detected" }
        "Windows10EsuUserConfirmed" {
            if ($Audit.WindowsSupport.EsuSignal -and $Audit.WindowsSupport.PostEosUpdateSignal) {
                $informationalItems += "Windows 10 ESU was user-confirmed; local supporting evidence was also detected from licensing text and post-EOS update history"
            }
            elseif ($Audit.WindowsSupport.PostEosUpdateSignal) {
                $informationalItems += "Windows 10 ESU was user-confirmed; local post-EOS update evidence was also detected"
            }
            elseif ($Audit.WindowsSupport.EsuSignal) {
                $informationalItems += "Windows 10 ESU was user-confirmed; a possible local ESU-related licensing signal was also detected"
            }
            else {
                $informationalItems += "Windows 10 ESU was user-confirmed; verify enrollment in Windows Update settings"
            }
        }
        "Windows10EsuSignalDetected" { $positiveSignals += "Possible local ESU-related licensing signal detected" }
        "Windows10EsuNotChecked" { $reviewItems += "Windows 10 ESU was not checked" }
        "Windows10EsuNotConfirmed" { $reviewItems += "Windows 10 ESU was not confirmed by local licensing text" }
        "Windows10NoEsuUserReported" { $actionItems += "Windows 10 ESU was reported as not enrolled" }
        "PossiblyUnsupported" { $actionItems += "Supported Windows servicing path is not confirmed" }
    }

    if ($Audit.UefiVariables.Detected2023Pattern) {
        $positiveSignals += "2023 Microsoft certificate text signal detected"
    }
    else {
        $reviewItems += "2023 certificate rollout was not locally confirmed"
    }

    $bitLockerSecureBootEvents = @($Audit.RelevantEvents | Where-Object { $_.ProviderName -match "BitLocker" -and $_.Message -match "Secure Boot|TCG Log|PCR7|integrity" })
    if (@($bitLockerSecureBootEvents).Count -gt 0) {
        $reviewItems += "BitLocker Secure Boot integrity warning events were detected"
    }
    elseif (@($Audit.RelevantEvents).Count -gt 0) {
        $reviewItems += "Recent relevant warnings/errors were found in event logs"
    }

    if (@($Audit.CollectionWarnings).Count -gt 0) {
        $reviewItems += "One or more non-fatal collection warnings occurred"
    }

    $technicalReadiness = if (($Audit.Firmware.FirmwareType -eq "UEFI") -and ($Audit.SecureBoot.Enabled -eq $true) -and ($Audit.BootManager.SignatureStatus -eq "Valid") -and ($Audit.Tpm.TpmReady -eq $true)) {
        "Strong"
    }
    elseif (($Audit.Firmware.FirmwareType -eq "UEFI") -and ($Audit.SecureBoot.Enabled -eq $true)) {
        "Good"
    }
    elseif ($Audit.Overall.Status -in @("ActionRequired", "Unsupported", "PossibleIntegrityIssue")) {
        "Action Required"
    }
    else {
        "Review Required"
    }

    return (New-AdvisorObject -Properties ([ordered]@{
        TechnicalReadiness = $technicalReadiness
        WindowsServicingPath = $Audit.WindowsSupport.ServicingPathSummary
        CertificateRolloutState = $Audit.CertificateDisplay.Status
        OverallStatus = $Audit.Overall.Status
        Note = "This is a categorical readiness rationale, not a numeric score, security score, or compliance attestation."
        PositiveSignals = @($positiveSignals | Select-Object -Unique)
        InformationalItems = @($informationalItems | Select-Object -Unique)
        ReviewItems = @($reviewItems | Select-Object -Unique)
        ActionItems = @($actionItems | Select-Object -Unique)
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-ExecutiveSummary
# Purpose : Summarizes the advisor result in plain language for quick review.
# Safety  : Presentation only.
# -----------------------------------------------------------------------------

function Get-ExecutiveSummary {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $secureBootPosture = if ($Audit.Firmware.FirmwareType -eq "UEFI" -and $Audit.SecureBoot.Enabled -eq $true -and $Audit.BootManager.SignatureStatus -eq "Valid") { "Healthy" } elseif ($Audit.SecureBoot.Enabled -eq $false) { "Needs attention" } else { "Review" }
    $tpmPosture = if ($Audit.Tpm.TpmReady -eq $true) { "Healthy" } else { "Review" }
    $bootIntegrity = if ($Audit.BootManager.SignatureStatus -eq "Valid") { "Healthy" } else { "Review" }
    $certificateState = if ($Audit.UefiVariables.Detected2023Pattern) { "Confirmed by text signal" } else { "Not locally confirmed" }

    return (New-AdvisorObject -Properties ([ordered]@{
        SecureBoot = $secureBootPosture
        TPM = $tpmPosture
        BootIntegrity = $bootIntegrity
        WindowsPath = $Audit.WindowsSupport.ServicingPathSummary
        CertificateState = $certificateState
        OverallRisk = $Audit.Overall.RiskLevel
        RecommendedAction = $Audit.Overall.NextAction
    }))
}

# -----------------------------------------------------------------------------
# Function: Get-ApplicableRemediationPlaybook
# Purpose : Filters remediation guidance to scenarios that are actually applicable to this audit.
# Safety  : Guidance only. No action.
# -----------------------------------------------------------------------------

function Get-ApplicableRemediationPlaybook {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $all = @($Audit.RemediationPlaybook)
    $applicable = @()
    $protectedVolumes = @($Audit.BitLocker.Volumes | Where-Object {
            $protectionStatus = [string]$_.ProtectionStatus
            $volumeStatus = [string]$_.VolumeStatus
            $encryptionPct = 0
            try { if ($_.EncryptionPercentage -ne $null) { $encryptionPct = [int]$_.EncryptionPercentage } } catch { $encryptionPct = 0 }

            ($protectionStatus -match "^(On|1|Protected)$") -or
            ($volumeStatus -match "EncryptionInProgress|FullyEncrypted|EncryptionPaused|DecryptionPaused|UsedSpaceOnlyEncrypted") -or
            ($encryptionPct -gt 0)
        })

    foreach ($step in $all) {
        $include = $false
        switch ($step.Scenario) {
            "Legacy BIOS mode" { $include = ($Audit.Firmware.FirmwareType -eq "BIOS") }
            "Secure Boot disabled" { $include = ($Audit.SecureBoot.Enabled -eq $false) }
            "2023 certificate signal missing or unknown" { $include = (-not $Audit.UefiVariables.Detected2023Pattern) }
            "BitLocker currently enabled" { $include = (@($protectedVolumes).Count -gt 0) }
            "BitLocker Secure Boot integrity warning events" { $include = (@($Audit.RelevantEvents | Where-Object { $_.ProviderName -match "BitLocker" -and $_.Message -match "Secure Boot|TCG Log|PCR7|integrity" }).Count -gt 0) }
            "Windows 10 ESU / servicing path review" { $include = ($Audit.WindowsSupport.Status -match "Windows10") }
            "Linux dual-boot suspected" { $include = $false }
            "Boot manager signature invalid" { $include = ($Audit.BootManager.SignatureStatus -and $Audit.BootManager.SignatureStatus -ne "Valid") }
        }
        if ($include) { $applicable += $step }
    }

    return @($applicable)
}

# -----------------------------------------------------------------------------
# Function: Get-NotApplicableRemediationScenarios
# Purpose : Lists scenarios intentionally not shown as actionable so users do not misread reference guidance.
# Safety  : Presentation only.
# -----------------------------------------------------------------------------

function Get-NotApplicableRemediationScenarios {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $applicableNames = @($Audit.ApplicableRemediation | ForEach-Object { $_.Scenario })
    return @($Audit.RemediationPlaybook | Where-Object { $applicableNames -notcontains $_.Scenario } | ForEach-Object { $_.Scenario })
}

#endregion Advisor rules and assessment

#region Report generation
# Purpose: create human-readable and machine-readable reports from the same structured audit object.
# -----------------------------------------------------------------------------
# Function: Export-FlatCsv
# Purpose : Writes summary and findings CSV files for fleet review or spreadsheet analysis.
# Safety  : Local report output only.
# -----------------------------------------------------------------------------

function Export-FlatCsv {
    param(
        [Parameter(Mandatory = $true)][object]$Audit,
        [Parameter(Mandatory = $true)][string]$SummaryPath,
        [Parameter(Mandatory = $true)][string]$FindingsPath
    )

    $summary = (New-AdvisorObject -Properties ([ordered]@{
        ToolName                    = $script:ToolName
        ToolVersion                 = $script:ToolVersion
        GeneratedAt                 = $Audit.GeneratedAt
        Mode                        = $Audit.Mode
        ComputerName                = $Audit.System.ComputerName
        Manufacturer                = $Audit.System.Manufacturer
        Model                       = $Audit.System.Model
        OSName                      = $Audit.System.OSName
        OSVersion                   = $Audit.System.OSVersion
        BuildNumber                 = $Audit.System.BuildNumber
        FirmwareType                = $Audit.Firmware.FirmwareType
        SecureBootEnabled           = $Audit.SecureBoot.Enabled
        BootManagerSignatureStatus  = $Audit.BootManager.SignatureStatus
        Uefi2023SignalDetected      = $Audit.UefiVariables.Detected2023Pattern
        Uefi2011SignalDetected      = $Audit.UefiVariables.Detected2011Pattern
        UEFICA2023Status            = $Audit.SecureBootRegistry.Specific.UEFICA2023Status
        UEFIRevocationListStatus    = $Audit.SecureBootRegistry.Specific.UEFIRevocationListStatus
        AvailableUpdates            = $Audit.SecureBootRegistry.Specific.AvailableUpdates
        WindowsSupportStatus        = $Audit.WindowsSupport.Status
        WindowsSupportPath          = $Audit.WindowsSupport.ServicingPathSummary
        UserDeclaredEsuStatus       = $Audit.WindowsSupport.UserDeclaredEsuStatus
        Windows10BuildEligibleForConsumerEsu = $Audit.WindowsSupport.Windows10BuildEligibleForConsumerEsu
        CertificateEligiblePath     = $Audit.CertificateRefresh.EligiblePath
        CertificateDeploymentState  = $Audit.CertificateRefresh.DeploymentState
        CertificateTransitionPhase  = $Audit.CertificateRefresh.TransitionPhase
        TpmPresent                  = $Audit.Tpm.TpmPresent
        TpmReady                    = $Audit.Tpm.TpmReady
        BitLockerVolumeCount        = @($Audit.BitLocker.Volumes).Count
        RelevantEventCount          = @($Audit.RelevantEvents).Count
        BitLockerSecureBootWarningCount = @($Audit.RelevantEvents | Where-Object { $_.ProviderName -match "BitLocker" -and $_.Message -match "Secure Boot|TCG Log|PCR7|integrity" }).Count
        CollectionWarningCount      = @($Audit.CollectionWarnings).Count
        OverallStatus               = $Audit.Overall.Status
        RiskLevel                   = $Audit.Overall.RiskLevel
        Confidence                  = $Audit.Overall.Confidence
        TechnicalReadiness          = $Audit.ReadinessRationale.TechnicalReadiness
        CertificateRolloutState     = $Audit.ReadinessRationale.CertificateRolloutState
        SecureBootPosture           = $Audit.ExecutiveSummary.SecureBoot
        CertificateDisplayStatus    = $Audit.CertificateDisplay.Status
        CertificateDisplayConfidence = $Audit.CertificateDisplay.Confidence
        EsuUserAssertion            = $Audit.EsuVerification.UserAssertion
        EsuLocalEvidence            = $Audit.EsuVerification.LocalEvidence
        EsuOverallConfidence        = $Audit.EsuVerification.OverallConfidence
        ApplicableRemediationCount  = @($Audit.ApplicableRemediation).Count
        NextAction                  = $Audit.Overall.NextAction
    }))

    $summary | Export-Csv -LiteralPath $SummaryPath -NoTypeInformation -Encoding UTF8 -Force
    $Audit.Findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, @{ Expression = 'Id'; Descending = $false } | Export-Csv -LiteralPath $FindingsPath -NoTypeInformation -Encoding UTF8 -Force
}


# -----------------------------------------------------------------------------
# Function: Get-SafeFileNameFragment
# Purpose : Sanitizes case IDs and file-name fragments used in handoff bundles.
# Safety  : Local string normalization only.
# -----------------------------------------------------------------------------

function Get-SafeFileNameFragment {
    param(
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $false)][string]$Fallback = "Bundle"
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $Fallback }
    $safe = $Value -replace '[^A-Za-z0-9_. -]', '_'
    $safe = $safe.Trim()
    if ([string]::IsNullOrWhiteSpace($safe)) { return $Fallback }
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
    return $safe
}

# -----------------------------------------------------------------------------
# Function: Resolve-BundleOutputPath
# Purpose : Determines the ZIP bundle path from -BundlePath, -CaseId, and default output settings.
# Safety  : Local path calculation only. No network paths are contacted unless explicitly provided by the admin.
# -----------------------------------------------------------------------------

function Resolve-BundleOutputPath {
    param(
        [Parameter(Mandatory = $true)][string]$DefaultDirectory,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$RequestedBundlePath,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$CaseId
    )

    $safeCaseId = if ([string]::IsNullOrWhiteSpace($CaseId)) { $null } else { Get-SafeFileNameFragment -Value $CaseId -Fallback "Case" }
    $bundleFileName = if ($safeCaseId) { "$safeCaseId-$BaseName-bundle.zip" } else { "$BaseName-bundle.zip" }

    if ([string]::IsNullOrWhiteSpace($RequestedBundlePath)) {
        return (Join-Path $DefaultDirectory $bundleFileName)
    }

    $extension = [System.IO.Path]::GetExtension($RequestedBundlePath)
    if ($extension -ieq ".zip") {
        return $RequestedBundlePath
    }

    return (Join-Path $RequestedBundlePath $bundleFileName)
}

# -----------------------------------------------------------------------------
# Function: New-ReportBundle
# Purpose : Creates a local ZIP bundle, manifest, and SHA256 hash file for admin handoff.
# Safety  : Local packaging only. This function never uploads or transmits data.
# -----------------------------------------------------------------------------

function New-ReportBundle {
    param(
        [Parameter(Mandatory = $true)][object]$Audit,
        [Parameter(Mandatory = $true)][string]$BundlePath,
        [Parameter(Mandatory = $true)][hashtable]$ReportPaths,
        [Parameter(Mandatory = $false)][switch]$IncludeSensitive,
        [Parameter(Mandatory = $false)][AllowEmptyString()][string]$CaseId
    )

    $bundleDirectory = Split-Path -Path $BundlePath -Parent
    if ([string]::IsNullOrWhiteSpace($bundleDirectory)) {
        $bundleDirectory = (Get-Location).Path
        $BundlePath = Join-Path $bundleDirectory (Split-Path -Path $BundlePath -Leaf)
    }
    if (-not (Test-Path -LiteralPath $bundleDirectory)) {
        New-Item -Path $bundleDirectory -ItemType Directory -Force | Out-Null
    }

    $bundleBase = [System.IO.Path]::GetFileNameWithoutExtension($BundlePath)
    $manifestPath = Join-Path $bundleDirectory "$bundleBase-manifest.json"
    $hashPath = Join-Path $bundleDirectory "$bundleBase-hashes.txt"
    $handoffReadmePath = Join-Path $bundleDirectory "$bundleBase-README-HANDOFF.txt"

    $included = @()
    $excludedSensitive = @()
    $candidateNames = @("TextReport", "HtmlReport", "JsonReport", "SummaryCsv", "FindingsCsv")
    foreach ($name in $candidateNames) {
        if ($ReportPaths.ContainsKey($name)) {
            $path = $ReportPaths[$name]
            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
                $included += $path
            }
        }
    }

    $sensitiveNames = @("LicenseDump", "Transcript")
    foreach ($name in $sensitiveNames) {
        if ($ReportPaths.ContainsKey($name)) {
            $path = $ReportPaths[$name]
            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
                if ($IncludeSensitive) {
                    $included += $path
                }
                else {
                    $excludedSensitive += (Split-Path -Path $path -Leaf)
                }
            }
        }
    }

    $included = @($included | Select-Object -Unique)

    $fileEntries = @()
    foreach ($path in $included) {
        try {
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
            $item = Get-Item -LiteralPath $path -ErrorAction Stop
            $fileEntries += (New-AdvisorObject -Properties ([ordered]@{
                Name      = $item.Name
                FullName  = (Protect-String -Value $item.FullName)
                Length    = $item.Length
                Sha256    = $hash.Hash
                Sensitive = ($sensitiveNames -contains ($ReportPaths.GetEnumerator() | Where-Object { $_.Value -eq $path } | Select-Object -First 1 -ExpandProperty Key))
            }))
        }
        catch {
            Add-CollectionWarning -Check "Bundle hashing" -Detail "Could not hash $path. $($_.Exception.Message)" -Recommendation "Review the file manually before sharing the bundle."
        }
    }

    $manifest = (New-AdvisorObject -Properties ([ordered]@{
        ToolName               = $script:ToolName
        ToolVersion            = $script:ToolVersion
        GeneratedAt            = (Get-Date).ToString("o")
        AuditGeneratedAt        = $Audit.GeneratedAt
        CaseId                 = $CaseId
        ComputerName            = $Audit.System.ComputerName
        Mode                   = $Audit.Mode
        RedactionEnabled        = $Audit.RedactionEnabled
        IncludesSensitiveFiles  = [bool]$IncludeSensitive
        NoNetworkTransfer       = $true
        TransferNote            = "This tool only creates a local bundle. Administrators control if, when, and how the bundle is transferred."
        HandoffReadme           = (Split-Path -Path $handoffReadmePath -Leaf)
        ExcludedSensitiveFiles  = @($excludedSensitive)
        Files                  = @($fileEntries)
    }))

    $manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $manifestPath -Encoding UTF8 -Force

    $hashLines = @()
    $hashLines += "# SHA256 hashes for Secure Boot Readiness Advisor handoff bundle"
    $hashLines += "# Generated: $((Get-Date).ToString('o'))"
    $hashLines += "# Bundle: $(Split-Path -Path $BundlePath -Leaf)"
    $hashLines += ""
    foreach ($entry in @($fileEntries)) {
        $hashLines += "$($entry.Sha256)  $($entry.Name)"
    }
    try {
        $manifestHash = Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop
        $hashLines += "$($manifestHash.Hash)  $(Split-Path -Path $manifestPath -Leaf)"
    }
    catch { }
    $hashLines | Out-File -LiteralPath $hashPath -Encoding UTF8 -Force

    $handoffLines = @()
    $handoffLines += "Secure Boot Readiness Advisor - Handoff README"
    $handoffLines += "Generated: $((Get-Date).ToString('o'))"
    $handoffLines += "Tool version: $script:ToolVersion"
    $handoffLines += "Case ID: $CaseId"
    $handoffLines += ""
    $handoffLines += "Recommended file to review first:"
    if ($ReportPaths.ContainsKey('HtmlReport') -and -not [string]::IsNullOrWhiteSpace($ReportPaths['HtmlReport'])) {
        $handoffLines += "- $(Split-Path -Path $ReportPaths['HtmlReport'] -Leaf)"
    }
    else {
        $handoffLines += "- $(Split-Path -Path $ReportPaths['TextReport'] -Leaf)"
    }
    $handoffLines += ""
    $handoffLines += "Sensitive files included: $([bool]$IncludeSensitive)"
    if ($excludedSensitive -and @($excludedSensitive).Count -gt 0) {
        $handoffLines += "Sensitive files excluded by default: $($excludedSensitive -join ', ')"
    }
    $handoffLines += ""
    $handoffLines += "Transfer policy: this tool created a local ZIP only. It did not upload or transmit report data. Administrators control if, when, and how this bundle is shared."
    $handoffLines += ""
    $handoffLines += "Integrity: compare files against the included SHA256 hashes before relying on transferred reports."
    $handoffLines | Out-File -LiteralPath $handoffReadmePath -Encoding UTF8 -Force

    try {
        $handoffHash = Get-FileHash -LiteralPath $handoffReadmePath -Algorithm SHA256 -ErrorAction Stop
        Add-Content -LiteralPath $hashPath -Encoding UTF8 -Value "$($handoffHash.Hash)  $(Split-Path -Path $handoffReadmePath -Leaf)"
    }
    catch { }

    $allBundleCandidates = @($included) + @($manifestPath) + @($hashPath) + @($handoffReadmePath)
    $bundleFiles = @($allBundleCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
    if (-not $bundleFiles -or $bundleFiles.Count -eq 0) {
        throw "No report files were available to bundle."
    }

    Compress-Archive -LiteralPath $bundleFiles -DestinationPath $BundlePath -Force

    return (New-AdvisorObject -Properties ([ordered]@{
        BundlePath             = $BundlePath
        ManifestPath           = $manifestPath
        HashPath               = $hashPath
        HandoffReadmePath      = $handoffReadmePath
        FileCount              = @($bundleFiles).Count
        IncludesSensitiveFiles = [bool]$IncludeSensitive
        ExcludedSensitiveFiles = @($excludedSensitive)
    }))
}

# -----------------------------------------------------------------------------
# Function: New-TextReport
# Purpose : Builds the plain-text report from the structured audit object.
# Safety  : Local report output only.
# -----------------------------------------------------------------------------

function New-TextReport {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $lines = @()
    $lines += "$script:ToolName v$script:ToolVersion"
    $lines += "Generated: $($Audit.GeneratedAt)"
    $lines += ""
    $lines += "EXECUTIVE SUMMARY"
    $lines += "Secure Boot       : $($Audit.ExecutiveSummary.SecureBoot)"
    $lines += "TPM               : $($Audit.ExecutiveSummary.TPM)"
    $lines += "Boot Integrity    : $($Audit.ExecutiveSummary.BootIntegrity)"
    $lines += "Windows Path      : $($Audit.ExecutiveSummary.WindowsPath)"
    $lines += "Certificate State : $($Audit.ExecutiveSummary.CertificateState)"
    $lines += "Technical Ready   : $($Audit.ReadinessRationale.TechnicalReadiness)"
    $lines += "Overall Risk      : $($Audit.ExecutiveSummary.OverallRisk)"
    $lines += "Recommended Action: $($Audit.ExecutiveSummary.RecommendedAction)"
    $lines += ""
    $lines += "OVERALL"
    $lines += "Status    : $(ConvertTo-DisplayLabel $Audit.Overall.Status)"
    $lines += "Risk      : $($Audit.Overall.RiskLevel)"
    $lines += "Confidence: $($Audit.Overall.Confidence)"
    $lines += "Headline  : $($Audit.Overall.Headline)"
    $lines += "Next step : $($Audit.Overall.NextAction)"
    $lines += ""
    $lines += "SYSTEM"
    $lines += "Computer  : $($Audit.System.ComputerName)"
    $lines += "Device    : $($Audit.System.Manufacturer) $($Audit.System.Model)"
    $lines += "OS        : $($Audit.System.OSName) $($Audit.System.OSVersion) Build $($Audit.System.BuildNumber)"
    $lines += "Win path  : $($Audit.WindowsSupport.ServicingPathSummary)"
    $lines += "ESU input : $($Audit.WindowsSupport.UserDeclaredEsuStatus)"
    $lines += "Firmware  : $($Audit.Firmware.FirmwareType)"
    $lines += "SecureBoot: $($Audit.SecureBoot.Enabled)"
    $lines += "Boot sig  : $($Audit.BootManager.SignatureStatus)"
    $lines += "2023 cert : $($Audit.CertificateDisplay.Status)"
    $lines += ""
    $lines += "ESU VERIFICATION"
    $lines += "User assertion     : $($Audit.EsuVerification.UserAssertion)"
    $lines += "Local evidence     : $($Audit.EsuVerification.LocalEvidence)"
    $lines += "Overall confidence : $($Audit.EsuVerification.OverallConfidence)"
    $lines += "Note               : $($Audit.EsuVerification.Note)"
    $lines += ""
    $lines += "CERTIFICATE STATUS"
    $lines += "Status           : $($Audit.CertificateDisplay.Status)"
    $lines += "Confidence       : $($Audit.CertificateDisplay.Confidence)"
    $lines += "Detection method : $($Audit.CertificateDisplay.DetectionMethod)"
    $lines += "Possible reasons :"
    foreach ($reason in @($Audit.CertificateDisplay.PossibleReasons)) { $lines += "- $reason" }
    $lines += ""
    $lines += "DEVICE CLASSIFICATION"
    $lines += "UEFI capable              : $($Audit.DeviceClassification.UefiCapable)"
    $lines += "Secure Boot ready         : $($Audit.DeviceClassification.SecureBootReady)"
    $lines += "BitLocker-compatible hint : $($Audit.DeviceClassification.BitLockerCompatibleSignal)"
    $lines += "Certificate refresh state : $(ConvertTo-DisplayLabel $Audit.DeviceClassification.CertificateRefreshState)"
    $lines += "Windows 11 note           : $($Audit.DeviceClassification.Windows11ReadinessNote)"
    $lines += ""
    $lines += "READINESS RATIONALE"
    $lines += "Technical readiness      : $($Audit.ReadinessRationale.TechnicalReadiness)"
    $lines += "Windows servicing path   : $($Audit.ReadinessRationale.WindowsServicingPath)"
    $lines += "Certificate rollout state: $($Audit.ReadinessRationale.CertificateRolloutState)"
    $lines += "Overall status           : $(ConvertTo-DisplayLabel $Audit.ReadinessRationale.OverallStatus)"
    $lines += "$($Audit.ReadinessRationale.Note)"
    $lines += ""
    $lines += "Positive signals:"
    if ($Audit.ReadinessRationale.PositiveSignals -and @($Audit.ReadinessRationale.PositiveSignals).Count -gt 0) {
        foreach ($item in @($Audit.ReadinessRationale.PositiveSignals)) { $lines += "+ $item" }
    }
    else { $lines += "None" }
    $lines += ""
    $lines += "Informational items:"
    if ($Audit.ReadinessRationale.InformationalItems -and @($Audit.ReadinessRationale.InformationalItems).Count -gt 0) {
        foreach ($item in @($Audit.ReadinessRationale.InformationalItems)) { $lines += "- $item" }
    }
    else { $lines += "None" }
    $lines += ""
    $lines += "Review items:"
    if ($Audit.ReadinessRationale.ReviewItems -and @($Audit.ReadinessRationale.ReviewItems).Count -gt 0) {
        foreach ($item in @($Audit.ReadinessRationale.ReviewItems)) { $lines += "! $item" }
    }
    else { $lines += "None" }
    $lines += ""
    $lines += "Action items:"
    if ($Audit.ReadinessRationale.ActionItems -and @($Audit.ReadinessRationale.ActionItems).Count -gt 0) {
        foreach ($item in @($Audit.ReadinessRationale.ActionItems)) { $lines += "! $item" }
    }
    else { $lines += "None" }
    $lines += ""
    $lines += "CERTIFICATE REFRESH CONTEXT"
    $lines += "Eligibility path : $($Audit.CertificateRefresh.EligiblePath)"
    $lines += "Eligibility      : $($Audit.CertificateRefresh.EligibilitySummary)"
    $lines += "Deployment state : $($Audit.CertificateRefresh.DeploymentState)"
    $lines += "Deployment note  : $($Audit.CertificateRefresh.DeploymentSummary)"
    $lines += "Timing           : $($Audit.CertificateRefresh.ExpectedTiming)"
    $lines += "Deadline meaning : $($Audit.CertificateRefresh.DeadlineMeaning)"
    $lines += "Admin purpose    : $($Audit.CertificateRefresh.AdminPreparationSummary)"
    $lines += ""
    $lines += "REPORT HANDOFF"
    if ($Audit.BundleSettings -and $Audit.BundleSettings.CreateBundle) {
        $lines += "Bundle requested : True"
        $lines += "Bundle path      : $($Audit.OutputFiles.BundleZip)"
        $lines += "Manifest path    : $($Audit.OutputFiles.BundleManifest)"
        $lines += "Hashes path      : $($Audit.OutputFiles.BundleHashes)"
        if ($Audit.OutputFiles.BundleHandoffReadme) { $lines += "Handoff README   : $($Audit.OutputFiles.BundleHandoffReadme)" }
        $lines += "Sensitive files  : $($Audit.BundleSettings.BundleIncludesSensitive)"
        $lines += "Transfer policy  : Local bundle only. This tool does not upload or transmit report data."
    }
    else {
        $lines += "Bundle requested : False"
        $lines += "Transfer policy  : Reports are written locally. This tool does not upload or transmit report data."
    }
    $lines += ""
    $lines += "COLLECTION WARNINGS"
    if ($Audit.CollectionWarnings -and @($Audit.CollectionWarnings).Count -gt 0) {
        foreach ($warning in @($Audit.CollectionWarnings)) { $lines += "- $($warning.Check): $($warning.Detail)" }
    }
    else { $lines += "None" }
    $lines += ""
    $lines += "FINDINGS"

    foreach ($finding in ($Audit.Findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, @{ Expression = 'Id'; Descending = $false })) {
        $lines += ""
        $lines += "[$($finding.Severity)] $($finding.Title)"
        $lines += "Category      : $($finding.Category)"
        $lines += "Detail        : $($finding.Detail)"
        $lines += "Recommendation: $($finding.Recommendation)"
        if ($finding.Evidence) { $lines += "Evidence      : $($finding.Evidence)" }
    }

    $lines += ""
    $lines += "TOP RELEVANT EVENTS"
    if ($Audit.RelevantEvents -and @($Audit.RelevantEvents).Count -gt 0) {
        $lines += "Showing up to 10 most recent unique matching warnings/errors. Review JSON/HTML for fuller detail."
        foreach ($event in @($Audit.RelevantEvents | Select-Object -First 10)) {
            $lines += ""
            $lines += "Time    : $($event.TimeCreated)"
            $lines += "Log     : $($event.LogName)"
            $lines += "Provider: $($event.ProviderName)"
            $lines += "Event ID: $($event.Id)"
            $lines += "Level   : $($event.LevelDisplay)"
            $lines += "Message : $(Get-ShortAdvisorText -Value $event.Message -MaxLength 320)"
        }
    }
    else { $lines += "No recent relevant warnings/errors were collected." }

    $lines += ""
    $lines += "APPLICABLE REMEDIATION GUIDANCE"
    $lines += "Only the following guidance appears applicable to this device's collected findings. This tool does not remediate automatically."
    if ($Audit.ApplicableRemediation -and @($Audit.ApplicableRemediation).Count -gt 0) {
        foreach ($step in @($Audit.ApplicableRemediation)) {
            $lines += ""
            $lines += "$($step.Scenario): $($step.Action)"
        }
    }
    else { $lines += "No conditional remediation guidance was triggered by this run." }

    $lines += ""
    $lines += "REFERENCE GUIDANCE NOT APPLICABLE TO THIS DEVICE"
    $lines += "These scenarios are part of the approved playbook but were not detected as applicable in this run."
    foreach ($scenario in @($Audit.NotApplicableRemediation)) { $lines += "- $scenario" }

    return ($lines -join [Environment]::NewLine)
}


# -----------------------------------------------------------------------------
# Function: New-HtmlReport
# Purpose : Builds the HTML report with summary cards, findings, warnings, events, and applicable remediation guidance.
# Safety  : Local report output only.
# -----------------------------------------------------------------------------

function New-HtmlReport {
    param([Parameter(Mandatory = $true)][object]$Audit)

    $statusClass = "status-unknown"
    switch ($Audit.Overall.Status) {
        "Ready" { $statusClass = "status-ready" }
        "ReviewRecommended" { $statusClass = "status-review" }
        "ActionRequired" { $statusClass = "status-action" }
        "Unsupported" { $statusClass = "status-action" }
        "PossibleIntegrityIssue" { $statusClass = "status-critical" }
        "InsufficientPermissions" { $statusClass = "status-review" }
    }
    $overallStatusDisplay = ConvertTo-DisplayLabel $Audit.Overall.Status
    $overallStatusForTitle = ConvertTo-HtmlSafe $overallStatusDisplay
    $certificateRefreshStateDisplay = ConvertTo-DisplayLabel $Audit.DeviceClassification.CertificateRefreshState
    $readinessOverallStatusDisplay = ConvertTo-DisplayLabel $Audit.ReadinessRationale.OverallStatus

    $findingRows = ""
    foreach ($finding in ($Audit.Findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, @{ Expression = 'Id'; Descending = $false })) {
        $findingRows += "<tr class='sev-$($finding.Severity.ToLower())'><td>$($finding.Id)</td><td>$($finding.Severity)</td><td>$(ConvertTo-HtmlSafe $finding.Category)</td><td>$(ConvertTo-HtmlSafe $finding.Title)</td><td>$(ConvertTo-HtmlSafe $finding.Detail)</td><td>$(ConvertTo-HtmlSafe $finding.Recommendation)</td></tr>`n"
    }

    $warningRows = ""
    foreach ($warning in @($Audit.CollectionWarnings)) {
        $warningRows += "<tr><td>$(ConvertTo-HtmlSafe $warning.Check)</td><td>$(ConvertTo-HtmlSafe $warning.Detail)</td><td>$(ConvertTo-HtmlSafe $warning.Recommendation)</td></tr>`n"
    }
    if (-not $warningRows) { $warningRows = "<tr><td colspan='3'>No collection warnings were recorded.</td></tr>" }

    $remediationRows = ""
    foreach ($step in @($Audit.ApplicableRemediation)) {
        $remediationRows += "<tr><td>$(ConvertTo-HtmlSafe $step.Scenario)</td><td>$(ConvertTo-HtmlSafe $step.Action)</td></tr>`n"
    }
    if (-not $remediationRows) { $remediationRows = "<tr><td colspan='2'>No conditional remediation guidance was triggered by this run.</td></tr>" }

    $notApplicableRows = ""
    foreach ($scenario in @($Audit.NotApplicableRemediation)) {
        $notApplicableRows += "<tr><td>$(ConvertTo-HtmlSafe $scenario)</td></tr>`n"
    }
    if (-not $notApplicableRows) { $notApplicableRows = "<tr><td>None</td></tr>" }

    $positiveRows = ""
    foreach ($item in @($Audit.ReadinessRationale.PositiveSignals)) { $positiveRows += "<li>$(ConvertTo-HtmlSafe $item)</li>`n" }
    if (-not $positiveRows) { $positiveRows = "<li>None</li>" }

    $infoRows = ""
    foreach ($item in @($Audit.ReadinessRationale.InformationalItems)) { $infoRows += "<li>$(ConvertTo-HtmlSafe $item)</li>`n" }
    if (-not $infoRows) { $infoRows = "<li>None</li>" }

    $reviewRows = ""
    foreach ($item in @($Audit.ReadinessRationale.ReviewItems)) { $reviewRows += "<li>$(ConvertTo-HtmlSafe $item)</li>`n" }
    if (-not $reviewRows) { $reviewRows = "<li>None</li>" }

    $actionRows = ""
    foreach ($item in @($Audit.ReadinessRationale.ActionItems)) { $actionRows += "<li>$(ConvertTo-HtmlSafe $item)</li>`n" }
    if (-not $actionRows) { $actionRows = "<li>None</li>" }

    $reasonRows = ""
    foreach ($reason in @($Audit.CertificateDisplay.PossibleReasons)) { $reasonRows += "<li>$(ConvertTo-HtmlSafe $reason)</li>`n" }
    if (-not $reasonRows) { $reasonRows = "<li>No additional reasons recorded.</li>" }

    $bitlockerRows = ""
    foreach ($volume in @($Audit.BitLocker.Volumes)) {
        $bitlockerRows += "<tr><td>$(ConvertTo-HtmlSafe $volume.MountPoint)</td><td>$(ConvertTo-HtmlSafe $volume.ProtectionStatus)</td><td>$(ConvertTo-HtmlSafe $volume.VolumeStatus)</td><td>$(ConvertTo-HtmlSafe $volume.EncryptionPercentage)</td><td>$(ConvertTo-HtmlSafe $volume.KeyProtectorTypes)</td><td>$(ConvertTo-HtmlSafe $volume.RecoveryPasswordProtectorFound)</td></tr>`n"
    }
    if (-not $bitlockerRows) { $bitlockerRows = "<tr><td colspan='6'>No BitLocker volume details collected.</td></tr>" }

    $uefiRows = ""
    foreach ($variable in @($Audit.UefiVariables.Variables)) {
        $uefiRows += "<tr><td>$(ConvertTo-HtmlSafe $variable.Name)</td><td>$(ConvertTo-HtmlSafe $variable.Readable)</td><td>$(ConvertTo-HtmlSafe $variable.ByteCount)</td><td>$(ConvertTo-HtmlSafe ($variable.TextMatches -join ', '))</td><td>$(ConvertTo-HtmlSafe $variable.Error)</td></tr>`n"
    }
    if (-not $uefiRows) { $uefiRows = "<tr><td colspan='5'>No UEFI variable details collected.</td></tr>" }

    $eventRows = ""
    foreach ($event in @($Audit.RelevantEvents | Select-Object -First 20)) {
        $eventRows += "<tr><td>$(ConvertTo-HtmlSafe $event.TimeCreated)</td><td>$(ConvertTo-HtmlSafe $event.LogName)</td><td>$(ConvertTo-HtmlSafe $event.ProviderName)</td><td>$(ConvertTo-HtmlSafe $event.Id)</td><td>$(ConvertTo-HtmlSafe $event.LevelDisplay)</td><td>$(ConvertTo-HtmlSafe (Get-ShortAdvisorText -Value $event.Message -MaxLength 600))</td></tr>`n"
    }
    if (-not $eventRows) { $eventRows = "<tr><td colspan='6'>No recent relevant warnings/errors were collected.</td></tr>" }

    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Secure Boot Readiness Advisor - $overallStatusForTitle</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 28px; background: #f6f8fb; color: #111827; }
h1 { margin-bottom: 4px; }
h2 { margin-top: 28px; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; }
.card { background: #ffffff; border: 1px solid #d1d5db; border-radius: 12px; padding: 18px; margin: 16px 0; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.badge { display: inline-block; padding: 8px 12px; border-radius: 999px; font-weight: 700; color: white; }
.status-ready { background: #166534; }
.status-review { background: #a16207; }
.status-action { background: #b45309; }
.status-critical { background: #991b1b; }
.status-unknown { background: #374151; }
table { width: 100%; border-collapse: collapse; background: white; margin-top: 10px; }
th, td { border: 1px solid #d1d5db; padding: 8px; vertical-align: top; font-size: 13px; }
th { background: #e5e7eb; text-align: left; }
.sev-critical td:first-child, .sev-high td:first-child { font-weight: 700; }
.sev-critical { background: #fee2e2; }
.sev-high { background: #ffedd5; }
.sev-medium { background: #fef3c7; }
.sev-low { background: #eff6ff; }
.sev-info { background: #ecfdf5; }
.small { color: #4b5563; font-size: 12px; }
.grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.metric { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; }
.metric .label { color: #6b7280; font-size: 12px; }
.metric .value { font-size: 18px; font-weight: 700; margin-top: 4px; }
pre { white-space: pre-wrap; background: #111827; color: #f9fafb; padding: 12px; border-radius: 8px; }
</style>
</head>
<body>
<h1>Secure Boot Readiness Advisor</h1>
<div class="small">Version $(ConvertTo-HtmlSafe $script:ToolVersion) | Generated $(ConvertTo-HtmlSafe $Audit.GeneratedAt) | Mode $(ConvertTo-HtmlSafe $Audit.Mode) | Redaction $(ConvertTo-HtmlSafe $Audit.RedactionEnabled)</div>

<div class="card">
    <span class="badge $statusClass">$overallStatusForTitle</span>
    <h2>$(ConvertTo-HtmlSafe $Audit.Overall.Headline)</h2>
    <p><strong>Risk:</strong> $(ConvertTo-HtmlSafe $Audit.Overall.RiskLevel) | <strong>Confidence:</strong> $(ConvertTo-HtmlSafe $Audit.Overall.Confidence)</p>
    <p><strong>Next action:</strong> $(ConvertTo-HtmlSafe $Audit.Overall.NextAction)</p>
</div>

<h2>Executive Summary</h2>
<div class="grid">
    <div class="metric"><div class="label">Secure Boot</div><div class="value">$(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.SecureBoot)</div></div>
    <div class="metric"><div class="label">TPM</div><div class="value">$(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.TPM)</div></div>
    <div class="metric"><div class="label">Boot Integrity</div><div class="value">$(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.BootIntegrity)</div></div>
    <div class="metric"><div class="label">Technical Readiness</div><div class="value">$(ConvertTo-HtmlSafe $Audit.ReadinessRationale.TechnicalReadiness)</div></div>
</div>
<div class="card">
<p><strong>Windows path:</strong> $(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.WindowsPath)</p>
<p><strong>Certificate state:</strong> $(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.CertificateState)</p>
<p><strong>Recommended action:</strong> $(ConvertTo-HtmlSafe $Audit.ExecutiveSummary.RecommendedAction)</p>
</div>

<h2>Readiness Rationale</h2>
<div class="card">
<p><strong>Technical readiness:</strong> $(ConvertTo-HtmlSafe $Audit.ReadinessRationale.TechnicalReadiness)</p>
<p><strong>Windows servicing path:</strong> $(ConvertTo-HtmlSafe $Audit.ReadinessRationale.WindowsServicingPath)</p>
<p><strong>Certificate rollout state:</strong> $(ConvertTo-HtmlSafe $Audit.ReadinessRationale.CertificateRolloutState)</p>
<p>$(ConvertTo-HtmlSafe $Audit.ReadinessRationale.Note)</p>
</div>
<table>
<tr><th>Category</th><th>Items</th></tr>
<tr><td>Positive signals</td><td><ul>$positiveRows</ul></td></tr>
<tr><td>Informational items</td><td><ul>$infoRows</ul></td></tr>
<tr><td>Review items</td><td><ul>$reviewRows</ul></td></tr>
<tr><td>Action items</td><td><ul>$actionRows</ul></td></tr>
</table>

<h2>Certificate Status</h2>
<div class="card">
<p><strong>Status:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateDisplay.Status)</p>
<p><strong>Confidence:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateDisplay.Confidence)</p>
<p><strong>Detection method:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateDisplay.DetectionMethod)</p>
<p><strong>Possible reasons if not confirmed:</strong></p>
<ul>$reasonRows</ul>
</div>

<h2>ESU Verification</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>User assertion</td><td>$(ConvertTo-HtmlSafe $Audit.EsuVerification.UserAssertion)</td></tr>
<tr><td>Local evidence</td><td>$(ConvertTo-HtmlSafe $Audit.EsuVerification.LocalEvidence)</td></tr>
<tr><td>Overall confidence</td><td>$(ConvertTo-HtmlSafe $Audit.EsuVerification.OverallConfidence)</td></tr>
<tr><td>Note</td><td>$(ConvertTo-HtmlSafe $Audit.EsuVerification.Note)</td></tr>
</table>

<h2>Device Classification</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>UEFI capable</td><td>$(ConvertTo-HtmlSafe $Audit.DeviceClassification.UefiCapable)</td></tr>
<tr><td>Secure Boot ready</td><td>$(ConvertTo-HtmlSafe $Audit.DeviceClassification.SecureBootReady)</td></tr>
<tr><td>BitLocker-compatible hint</td><td>$(ConvertTo-HtmlSafe $Audit.DeviceClassification.BitLockerCompatibleSignal)</td></tr>
<tr><td>Certificate refresh state</td><td>$(ConvertTo-HtmlSafe $certificateRefreshStateDisplay)</td></tr>
<tr><td>Windows 11 readiness note</td><td>$(ConvertTo-HtmlSafe $Audit.DeviceClassification.Windows11ReadinessNote)</td></tr>
</table>

<h2>Certificate Refresh Context</h2>
<div class="card">
<p><strong>Eligibility path:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.EligiblePath)</p>
<p><strong>Eligibility:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.EligibilitySummary)</p>
<p><strong>Deployment state:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.DeploymentState)</p>
<p><strong>Deployment note:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.DeploymentSummary)</p>
<p><strong>Expected timing:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.ExpectedTiming)</p>
<p><strong>What the deadline means:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.DeadlineMeaning)</p>
<p><strong>How this prepares admins:</strong> $(ConvertTo-HtmlSafe $Audit.CertificateRefresh.AdminPreparationSummary)</p>
</div>

<h2>System Summary</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Computer</td><td>$(ConvertTo-HtmlSafe $Audit.System.ComputerName)</td></tr>
<tr><td>Device</td><td>$(ConvertTo-HtmlSafe "$($Audit.System.Manufacturer) $($Audit.System.Model)")</td></tr>
<tr><td>OS</td><td>$(ConvertTo-HtmlSafe "$($Audit.System.OSName) $($Audit.System.OSVersion) Build $($Audit.System.BuildNumber)")</td></tr>
<tr><td>BIOS/UEFI</td><td>$(ConvertTo-HtmlSafe "$($Audit.System.SMBIOSBIOSVersion) | Release $($Audit.System.BIOSReleaseDate) | Age $($Audit.System.BIOSAgeDays) days")</td></tr>
<tr><td>Windows support posture</td><td>$(ConvertTo-HtmlSafe "$($Audit.WindowsSupport.Status): $($Audit.WindowsSupport.Detail)")</td></tr>
<tr><td>Windows servicing path</td><td>$(ConvertTo-HtmlSafe $Audit.WindowsSupport.ServicingPathSummary)</td></tr>
<tr><td>User-declared Windows 10 ESU status</td><td>$(ConvertTo-HtmlSafe $Audit.WindowsSupport.UserDeclaredEsuStatus)</td></tr>
</table>

<h2>Collection Warnings</h2>
<table><tr><th>Check</th><th>Detail</th><th>Recommendation</th></tr>$warningRows</table>

<h2>Findings</h2>
<table><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>$findingRows</table>

<h2>Applicable Remediation Guidance</h2>
<p>Only the guidance below appears applicable to this device based on collected findings. This section replaces the previous full static playbook to avoid implying unrelated scenarios were detected.</p>
<table><tr><th>Scenario</th><th>Approved Action</th></tr>$remediationRows</table>

<h2>Reference Guidance Not Applicable To This Device</h2>
<p>These approved playbook scenarios were not detected as applicable in this run.</p>
<table><tr><th>Scenario</th></tr>$notApplicableRows</table>

<h2>BitLocker</h2>
<table><tr><th>Mount</th><th>Protection</th><th>Volume</th><th>Encrypted %</th><th>Protector Types</th><th>Recovery Password Protector Found</th></tr>$bitlockerRows</table>

<h2>UEFI Variable Signals</h2>
<table><tr><th>Name</th><th>Readable</th><th>Bytes</th><th>Text Matches</th><th>Error</th></tr>$uefiRows</table>

<h2>Top Relevant Event Warnings/Errors</h2>
<p>Showing up to 20 recent unique matching events. These are advisory leads for admin review, not automatic proof of a Secure Boot problem.</p>
<table><tr><th>Time</th><th>Log</th><th>Provider</th><th>ID</th><th>Level</th><th>Message</th></tr>$eventRows</table>

<div class="card small">
<strong>Safety note:</strong> This tool is read-only. It does not change Secure Boot, UEFI variables, BitLocker, boot configuration, firmware, or update state. Treat recommendations as advisory and validate against Microsoft, OEM, and organizational guidance before production remediation.
</div>
</body>
</html>
"@
}

#endregion Report generation

#region Main execution

# Purpose: coordinate evidence collection, advisor evaluation, report writing, optional UI, and cleanup.

# Main execution
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$computerForFile = if ($env:COMPUTERNAME) { $env:COMPUTERNAME -replace '[^A-Za-z0-9_-]', '_' } else { "UnknownComputer" }

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

if ($Explain) {
    Show-AdvisorExplanation
    return
}

$baseName = "SecureBootAdvisor-$computerForFile-$timestamp"
$jsonPath = Join-Path $OutputDirectory "$baseName.json"
$htmlPath = Join-Path $OutputDirectory "$baseName.html"
$txtPath = Join-Path $OutputDirectory "$baseName.txt"
$summaryCsvPath = Join-Path $OutputDirectory "$baseName-summary.csv"
$findingsCsvPath = Join-Path $OutputDirectory "$baseName-findings.csv"
$slmgrPath = Join-Path $OutputDirectory "$baseName-slmgr.txt"
$transcriptPath = Join-Path $OutputDirectory "$baseName-transcript.txt"
$resolvedBundlePath = Resolve-BundleOutputPath -DefaultDirectory $OutputDirectory -BaseName $baseName -RequestedBundlePath $BundlePath -CaseId $CaseId
$resolvedBundleDirectory = Split-Path -Path $resolvedBundlePath -Parent
if ([string]::IsNullOrWhiteSpace($resolvedBundleDirectory)) { $resolvedBundleDirectory = $OutputDirectory }
$bundleManifestPath = Join-Path $resolvedBundleDirectory "$([System.IO.Path]::GetFileNameWithoutExtension($resolvedBundlePath))-manifest.json"
$bundleHashesPath = Join-Path $resolvedBundleDirectory "$([System.IO.Path]::GetFileNameWithoutExtension($resolvedBundlePath))-hashes.txt"

$transcriptStarted = $false
if (-not $NoTranscript -and $Mode -ne "Fleet") {
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        $transcriptStarted = $true
    }
    catch { }
}

try {
    if ($Interactive -and $Mode -ne "Fleet") {
        $interactiveResult = Invoke-AdvisorInteractivePrompt -CurrentMode $Mode -CurrentWindows10EsuStatus $Windows10EsuStatus -CurrentIncludeLicenseDetails ([bool]$IncludeLicenseDetails) -CurrentOpenReport ([bool]$OpenReport)
        if ($interactiveResult.Cancelled) {
            Write-Console "Interactive run cancelled by user." "Yellow"
            return
        }
        $Mode = $interactiveResult.Mode
        $Windows10EsuStatus = $interactiveResult.Windows10EsuStatus
        if ($interactiveResult.IncludeLicenseDetails) { $IncludeLicenseDetails = $true }
        if ($interactiveResult.OpenReport) { $OpenReport = $true }
    }

    Write-Section "Secure Boot Readiness Advisor"
    Write-Console "Collecting read-only evidence. No remediation will be performed." "Yellow"

    # Collector phase 1: baseline identity and boot posture.
    # These checks establish whether the device is UEFI-capable, Secure Boot-enabled, and running a supported Windows build.
    $isAdmin = Test-IsAdministrator
    $system = Get-SystemInventory
    $firmware = Get-FirmwareMode
    $secureBoot = Get-SecureBootState
    if ($firmware.FirmwareType -eq "Unknown" -and $null -ne $secureBoot.Enabled) {
        $firmware.FirmwareType = "UEFI"
        $firmware.DetectionMethod = "Confirm-SecureBootUEFI"
        $firmware.Confidence = "Medium"
        Add-CollectionWarning -Check "Firmware mode fallback" -Detail "Firmware mode was inferred as UEFI because Confirm-SecureBootUEFI returned a value." -Recommendation "Use System Information or firmware setup to confirm if a higher-confidence firmware mode signal is required."
    }
    # Collector phase 2: Secure Boot servicing and certificate signals.
    # Missing 2023 text markers are treated as advisory because UEFI data is binary and rollout is phased.
    $secureBootRegistry = Get-SecureBootRegistryIndicators
    $uefiVariables = Get-UefiVariableSignals
    $bootManager = Get-BootManagerSignature -DriveLetter $EspDriveLetter -SkipMount:$SkipEspMount
    # Collector phase 3: remediation safety context.
    # BitLocker, TPM, Device Guard, update history, and event logs help admins avoid unsafe firmware or boot changes.
    $bitLocker = Get-BitLockerSummary
    $tpm = Get-TpmSummary
    $deviceGuard = Get-DeviceGuardSummary
    $hotfixes = Get-RecentHotfixSummary
    $events = Get-RelevantEventSummary -Days $EventLogDays -MaxEvents $MaxEventsPerLog

    $licenseSignal = (New-AdvisorObject -Properties ([ordered]@{
        Collected = $false
        Path      = $null
        EsuLines  = @()
        Error     = $null
    }))

    # Optional collector phase: licensing/ESU hints.
    # Kept behind -IncludeLicenseDetails because slmgr output may include environment-specific identifiers.
    if ($IncludeLicenseDetails) {
        $licenseSignal = Invoke-LicenseSignalCollection -Path $slmgrPath
    }

    # Interpretation phase: convert raw evidence into support-path and certificate-rollout context.
    # This is where Windows 10 ESU state and Microsoft phased deployment timing are separated from local boot health.
    $windowsSupport = Get-WindowsSupportPosture -SystemInventory $system -EsuLines $licenseSignal.EsuLines -LicenseDetailsCollected:$licenseSignal.Collected -RecentHotfixes $hotfixes -UserDeclaredEsuStatus $Windows10EsuStatus
    $certificateRefresh = Get-CertificateRefreshContext -SystemInventory $system -Firmware $firmware -SecureBoot $secureBoot -UefiVariables $uefiVariables -WindowsSupport $windowsSupport

    $audit = (New-AdvisorObject -Properties ([ordered]@{
        ToolName             = $script:ToolName
        ToolVersion          = $script:ToolVersion
        GeneratedAt          = (Get-Date).ToString("o")
        Mode                 = $Mode
        RedactionEnabled     = $Redact
        BundleSettings       = (New-AdvisorObject -Properties ([ordered]@{
            CreateBundle = [bool]$CreateBundle
            BundleIncludesSensitive = [bool]$BundleIncludesSensitive
            BundlePath = if ($CreateBundle) { Protect-String -Value $resolvedBundlePath } else { $null }
            CaseId = $CaseId
            NoNetworkTransfer = $true
        }))
        Windows10EsuStatusParameter = $Windows10EsuStatus
        IsAdministrator      = $isAdmin
        System               = $system
        Firmware             = $firmware
        SecureBoot           = $secureBoot
        SecureBootRegistry   = $secureBootRegistry
        UefiVariables        = $uefiVariables
        BootManager          = $bootManager
        BitLocker            = $bitLocker
        Tpm                  = $tpm
        DeviceGuard          = $deviceGuard
        WindowsSupport       = $windowsSupport
        CertificateRefresh   = $certificateRefresh
        RecentHotfixes       = @($hotfixes)
        RelevantEvents       = @($events)
        LicenseSignal        = $licenseSignal
        RemediationPlaybook  = Get-ApprovedRemediationPlaybook
        ApplicableRemediation = @()
        NotApplicableRemediation = @()
        ReadinessRationale   = $null
        ExecutiveSummary     = $null
        CertificateDisplay   = $null
        EsuVerification      = $null
        DeviceClassification = $null
        CollectionWarnings   = @($script:CollectionWarnings)
        Findings             = @()
        Overall              = $null
        OutputFiles          = $null
    }))

    # Advisor phase: apply deterministic rules and calculate the final status/risk/confidence.
    # No LLM, remediation, firmware writing, or system modification occurs here.
    Invoke-AdvisorRules -Audit $audit
    $audit.Findings = @($script:Findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, @{ Expression = 'Id'; Descending = $false })
    $audit.Overall = Get-OverallAssessment -Audit $audit
    $audit.CertificateDisplay = Get-CertificateDisplayStatus -Audit $audit
    $audit.EsuVerification = Get-EsuVerificationSummary -Audit $audit
    $audit.DeviceClassification = Get-DeviceClassification -Audit $audit
    $audit.ReadinessRationale = Get-ReadinessRationale -Audit $audit
    $audit.ExecutiveSummary = Get-ExecutiveSummary -Audit $audit
    $audit.ApplicableRemediation = @(Get-ApplicableRemediationPlaybook -Audit $audit)
    $audit.NotApplicableRemediation = @(Get-NotApplicableRemediationScenarios -Audit $audit)

    $outputFiles = [ordered]@{
        TextReport  = (Protect-String -Value $txtPath)
        JsonReport  = if (-not $NoJson) { Protect-String -Value $jsonPath } else { $null }
        HtmlReport  = if (-not $NoHtml) { Protect-String -Value $htmlPath } else { $null }
        SummaryCsv  = if (-not $NoCsv) { Protect-String -Value $summaryCsvPath } else { $null }
        FindingsCsv = if (-not $NoCsv) { Protect-String -Value $findingsCsvPath } else { $null }
        LicenseDump = if ($IncludeLicenseDetails) { Protect-String -Value $slmgrPath } else { $null }
        Transcript  = if ($transcriptStarted) { Protect-String -Value $transcriptPath } else { $null }
        BundleZip   = if ($CreateBundle) { Protect-String -Value $resolvedBundlePath } else { $null }
        BundleManifest = if ($CreateBundle) { Protect-String -Value $bundleManifestPath } else { $null }
        BundleHashes = if ($CreateBundle) { Protect-String -Value $bundleHashesPath } else { $null }
        BundleHandoffReadme = if ($CreateBundle) { Protect-String -Value (Join-Path $resolvedBundleDirectory "$([System.IO.Path]::GetFileNameWithoutExtension($resolvedBundlePath))-README-HANDOFF.txt") } else { $null }
    }
    $audit.OutputFiles = (New-AdvisorObject -Properties $outputFiles)

    # Reporting phase: generate the human-readable and machine-readable outputs from the same audit object.
    $textReport = New-TextReport -Audit $audit
    $textReport | Out-File -LiteralPath $txtPath -Encoding UTF8 -Force

    if (-not $NoJson) {
        $audit | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding UTF8 -Force
    }

    if (-not $NoHtml) {
        $html = New-HtmlReport -Audit $audit
        $html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -Force
    }

    if (-not $NoCsv) {
        Export-FlatCsv -Audit $audit -SummaryPath $summaryCsvPath -FindingsPath $findingsCsvPath
    }

    $bundleResult = $null
    if ($CreateBundle) {
        # Handoff packaging phase: create a local ZIP, manifest, and hash list after all reports are written.
        # If sensitive files are requested, stop the transcript first so it can be included cleanly.
        if ($BundleIncludesSensitive -and $transcriptStarted) {
            try { Stop-Transcript | Out-Null } catch { }
            $transcriptStarted = $false
        }

        $reportPathMap = @{
            TextReport = $txtPath
            HtmlReport = if (-not $NoHtml) { $htmlPath } else { $null }
            JsonReport = if (-not $NoJson) { $jsonPath } else { $null }
            SummaryCsv = if (-not $NoCsv) { $summaryCsvPath } else { $null }
            FindingsCsv = if (-not $NoCsv) { $findingsCsvPath } else { $null }
            LicenseDump = if ($IncludeLicenseDetails) { $slmgrPath } else { $null }
            Transcript = if (Test-Path -LiteralPath $transcriptPath) { $transcriptPath } else { $null }
        }

        try {
            $bundleResult = New-ReportBundle -Audit $audit -BundlePath $resolvedBundlePath -ReportPaths $reportPathMap -IncludeSensitive:$BundleIncludesSensitive -CaseId $CaseId
        }
        catch {
            Add-CollectionWarning -Check "Bundle creation" -Detail "Could not create the report bundle. $($_.Exception.Message)" -Recommendation "Use the individual report files or rerun with a writable BundlePath."
            Write-Console "Bundle creation failed: $($_.Exception.Message)" "Yellow"
        }
    }

    if ($Mode -eq "Fleet") {
        $fleetObject = (New-AdvisorObject -Properties ([ordered]@{
            ToolName       = $script:ToolName
            ToolVersion    = $script:ToolVersion
            GeneratedAt    = $audit.GeneratedAt
            ComputerName   = $audit.System.ComputerName
            FirmwareType   = $audit.Firmware.FirmwareType
            SecureBoot     = $audit.SecureBoot.Enabled
            Uefi2023Signal = $audit.UefiVariables.Detected2023Pattern
            BootSignature  = $audit.BootManager.SignatureStatus
            WindowsSupport = $audit.WindowsSupport.Status
            WindowsSupportPath = $audit.WindowsSupport.ServicingPathSummary
            UserDeclaredEsuStatus = $audit.WindowsSupport.UserDeclaredEsuStatus
            CertificateEligiblePath = $audit.CertificateRefresh.EligiblePath
            CertificateDeploymentState = $audit.CertificateRefresh.DeploymentState
            CertificateTransitionPhase = $audit.CertificateRefresh.TransitionPhase
            OverallStatus  = $audit.Overall.Status
            RiskLevel      = $audit.Overall.RiskLevel
            Confidence     = $audit.Overall.Confidence
            TechnicalReadiness = $audit.ReadinessRationale.TechnicalReadiness
            SecureBootPosture = $audit.ExecutiveSummary.SecureBoot
            CertificateDisplayStatus = $audit.CertificateDisplay.Status
            CollectionWarnings = @($audit.CollectionWarnings).Count
            BundleCreated  = [bool]($CreateBundle -and $null -ne $bundleResult)
            BundlePath     = if ($bundleResult) { $bundleResult.BundlePath } else { $null }
            NextAction     = $audit.Overall.NextAction
        }))
        $fleetObject | ConvertTo-Json -Compress -Depth 4
    }
    else {
        Write-Section "Assessment"
        Write-Console "Status     : $(ConvertTo-DisplayLabel $audit.Overall.Status)" "Green"
        Write-Console "Risk       : $($audit.Overall.RiskLevel)" "Green"
        Write-Console "Confidence : $($audit.Overall.Confidence)" "Green"
        Write-Console "Headline   : $($audit.Overall.Headline)" "White"
        Write-Console "Next action: $($audit.Overall.NextAction)" "Yellow"
        Write-Console "" "Gray"
        Write-Console "Executive summary" "White"
        Write-Console "Secure Boot posture : $($audit.ExecutiveSummary.SecureBoot) (Firmware=$($audit.Firmware.FirmwareType); SecureBoot=$($audit.SecureBoot.Enabled); BootSig=$($audit.BootManager.SignatureStatus))" "Cyan"
        Write-Console "Windows update path : $($audit.WindowsSupport.ServicingPathSummary)" "Cyan"
        Write-Console "ESU verification    : User=$($audit.EsuVerification.UserAssertion); Local=$($audit.EsuVerification.LocalEvidence); Confidence=$($audit.EsuVerification.OverallConfidence)" "Cyan"
        Write-Console "Certificate rollout : $($audit.CertificateDisplay.Status) ($($audit.CertificateRefresh.DeploymentState))" "Cyan"
        Write-Console "Technical readiness : $($audit.ReadinessRationale.TechnicalReadiness)" "Cyan"
        Write-Console "Relevant events     : $(@($audit.RelevantEvents).Count)" "Cyan"
        Write-Console "Timing interpretation: Phased monthly Windows Update rollout; no per-device install date is guaranteed by this tool." "Cyan"

        Write-Section "Report Files"
        Write-Console "Text report : $txtPath" "Gray"
        if (-not $NoHtml) { Write-Console "HTML report : $htmlPath" "Gray" }
        if (-not $NoJson) { Write-Console "JSON report : $jsonPath" "Gray" }
        if (-not $NoCsv) {
            Write-Console "CSV summary : $summaryCsvPath" "Gray"
            Write-Console "CSV findings: $findingsCsvPath" "Gray"
        }
        if ($IncludeLicenseDetails) { Write-Console "License dump: $slmgrPath" "Gray" }
        if ($CreateBundle) {
            if ($bundleResult) {
                Write-Console "Bundle ZIP : $($bundleResult.BundlePath)" "Gray"
                Write-Console "Manifest   : $($bundleResult.ManifestPath)" "Gray"
                Write-Console "Hashes     : $($bundleResult.HashPath)" "Gray"
                if ($bundleResult.HandoffReadmePath) { Write-Console "Handoff README: $($bundleResult.HandoffReadmePath)" "Gray" }
                if (-not $BundleIncludesSensitive -and $bundleResult.ExcludedSensitiveFiles -and @($bundleResult.ExcludedSensitiveFiles).Count -gt 0) {
                    Write-Console "Sensitive files were excluded from the bundle by default." "Yellow"
                }
            }
            else {
                Write-Console "Bundle ZIP : Not created" "Yellow"
            }
        }
    }

    if ($Interactive -and $Mode -ne "Fleet") {
        $completionReportPath = if (-not $NoHtml) { $htmlPath } else { $txtPath }
        Show-AdvisorCompletionDialog -Audit $audit -HtmlReportPath $completionReportPath
    }

    if ($OpenReport -and -not $NoHtml -and (Test-Path -LiteralPath $htmlPath)) {
        Start-Process -FilePath $htmlPath | Out-Null
    }
}
finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}
#endregion Main execution