# Changelog

## v2.0.16

- Improved relevant event de-duplication using normalized timestamp, provider, event ID, and message content instead of relying on raw event record identity.
- Split current BitLocker protection guidance from historical/current BitLocker Secure Boot integrity warning guidance.
- Updated BitLocker Event ID 815 guidance so historical event log entries do not imply BitLocker is currently enabled.
- Softened Windows 10 ESU applicable-remediation wording to "Windows 10 ESU / servicing path review" when ESU is user-confirmed or post-EOS update evidence is present.
- Tightened current BitLocker detection so key protector metadata alone does not classify a volume as currently protected when protection is off and the volume is fully decrypted.

## v2.0.15

- Refined Windows 10 ESU wording when the operator declares ESU enrollment and the tool also finds local supporting evidence such as post-end-of-support KB update history.
- Updated ESU Verification notes to distinguish user-declared enrollment, local supporting evidence, and final verification in Windows Update settings.
- Updated readiness rationale so user-confirmed ESU with local evidence does not sound like user-confirmed-only context.
- Added ESU text-signal and post-EOS update-signal fields to the Windows Support finding evidence.
- No remediation behavior changed. The script remains read-only and local-only.

## v2.0.13

- Fixed a parser error in `-Explain` caused by an unescaped quoted `-CaseId` example string.
- No evidence collection or advisor logic changes from v2.0.12.

## v2.0.12

- Removed the numeric readiness score to avoid false precision.
- Replaced score/factor output with categorical readiness rationale: positive signals, informational items, review items, and action items.
- Updated TXT, HTML, CSV, Fleet, and console output to use technical readiness and certificate rollout categories instead of points.
- Deduplicated relevant event log entries before reporting.
- Improved BitLocker applicability logic so BitLocker guidance is not incorrectly marked non-applicable when protected-volume or BitLocker Secure Boot integrity signals are present.

## v2.0.11

- Added Executive Summary to TXT and HTML reports.
- Added readiness score with scoring factors.
- Added certificate display status with confidence and possible reasons when the rollout is not confirmed.
- Added ESU verification summary separating user-declared ESU status from local licensing evidence.
- Added device classification section without overclaiming full Windows 11 compatibility.
- Added top relevant event details to the TXT report and clarified HTML event table language.
- Replaced the full static remediation appendix with applicable-only remediation guidance.
- Added a reference section listing remediation scenarios not applicable to the current device.
- Added `-Explain` mode for a plain-English overview without collecting evidence.
- Added `README-HANDOFF.txt` to local report bundles.
- Added readiness and certificate/ESU fields to CSV/Fleet output.
- Fixed duplicated BundleIncludesSensitive branch inherited from earlier build.

## v2.0.10

- Added `-CreateBundle` to generate a local ZIP handoff bundle.
- Added `-BundleIncludesSensitive` to intentionally include sensitive local-only files such as transcript and raw `slmgr` output.
- Added `-BundlePath` for custom bundle destination paths or directories.
- Added `-CaseId` for ticket, pilot, wave, or change identifiers in bundle names and manifest metadata.
- Added bundle manifest generation with report metadata, file list, redaction state, and a no-network-transfer statement.
- Added SHA256 hash file generation for bundle contents.
- Added Report Handoff sections to TXT and HTML reports.
- Added console output for bundle ZIP, manifest, and hash paths.
- Documented manual SFTP/SCP transfer examples in README while keeping the script itself local-only and non-uploading.

## v2.0.9

- Added extensive human-readable script markup using PowerShell `#region` / `#endregion` blocks.
- Added function banners with `Purpose` and `Safety` notes for each function.
- Added a script architecture map in the comment-based help header.
- Added inline comments in the main execution flow to explain collector, interpretation, advisor, and reporting phases.
- Updated README with script readability notes and current interactive/ESU usage examples.
- No intended evidence-collection or advisor-logic behavior changes from v2.0.8.

## v2.0.8

- Fixed empty-string console output failure.
- Added optional `-Interactive` Windows Forms guided mode.
- Added completion dialog for local/manual use.
- Kept Fleet mode non-interactive.

## v2.0.7

- Added certificate refresh context and clearer rollout timing interpretation.
- Clarified that missing 2023 certificate text signal is not proof of update failure.
- Improved console output separation between Secure Boot posture, Windows update path, and certificate rollout state.

## v2.0.6

- Added `-Windows10EsuStatus Unknown|Enrolled|NotEnrolled` for user-declared Windows 10 ESU context.
- Changed Windows 10 messaging from vague supported-path language to explicit ESU verification language.
- Added Windows 10 22H2/build eligibility signal to support posture output.
- Added Windows support path and ESU input fields to TXT, HTML, CSV, JSON, and Fleet output.
- Lowered simple 2023 certificate text-scan absence to a Low review signal when no stronger evidence exists.
- Improved firmware evidence wording when `PEFirmwareType` is missing and UEFI is inferred through fallback evidence.
- Updated remediation guidance for Windows 10 ESU-not-verified/not-enrolled scenarios.
