# detection-as-code

![detections](https://github.com/fariselkhatib/detection-as-code/actions/workflows/tests.yml/badge.svg)

Sigma detections managed like software: every rule is validated, unit-tested against true-positive and false-positive events, converted to Splunk and Microsoft KQL, and mapped to ATT&CK, all in CI. A rule that misses its attack, fires on benign activity, or won't convert can't merge.

## Why

Most detection backlogs fail the same way: rules get written straight into a SIEM, nobody knows if they still fire after a log schema change, and false positives get "fixed" by someone deleting the rule at 2am. Treating detections as code fixes that. Rules live in git, changes get reviewed, and tests prove behavior before anything hits production.

These rules are drawn from what actually shows up in ransomware and BEC investigations: the exfil, staging, credential theft, and anti-forensics steps that sit between initial access and impact.

## The pipeline

```
rules/*.yml ──► validate ──► test against fixtures ──► convert (pySigma) ──► docs
               (metadata,     (must fire on every TP,    (Splunk, Defender     (queries.md,
                ATT&CK tags,   stay quiet on every FP)    XDR KQL, Sentinel)    coverage.md)
                fixture exists)
```

All four stages run in one `pytest` invocation, locally and in GitHub Actions.

## Rules

| Rule | Level | ATT&CK |
|---|---|---|
| [Rclone copy/sync to a cloud remote](rules/windows/process_creation/proc_creation_win_rclone_cloud_exfil.yml) | high | T1567.002 |
| [Password-protected archive via 7-Zip / RAR](rules/windows/process_creation/proc_creation_win_7zip_password_archive.yml) | medium | T1560.001 |
| [Shadow copy deletion or resize](rules/windows/process_creation/proc_creation_win_shadow_copy_deletion.yml) | critical | T1490 |
| [LSASS dump via comsvcs MiniDump](rules/windows/process_creation/proc_creation_win_lsass_dump_comsvcs.yml) | critical | T1003.001 |
| [Office app spawns encoded PowerShell](rules/windows/process_creation/proc_creation_win_office_spawns_encoded_powershell.yml) | high | T1059.001, T1566.001 |
| [Domain Admins enumeration via net](rules/windows/process_creation/proc_creation_win_domain_admin_group_enum.yml) | low | T1069.002 |
| [Security audit log cleared (1102)](rules/windows/builtin/win_security_audit_log_cleared.yml) | high | T1070.001 |
| [PsExec service installed (7045)](rules/windows/builtin/win_system_psexec_service_install.yml) | medium | T1569.002, T1021.002 |
| [CloudTrail or GuardDuty disabled](rules/cloud/aws/aws_cloudtrail_logging_disabled.yml) | high | T1562.008 |
| [Inbox rule hides mail in RSS / Conversation History](rules/cloud/m365/m365_exchange_hiding_inbox_rule.yml) | high | T1564.008 |

Full matrix and gaps: [docs/coverage.md](docs/coverage.md). Converted queries: [docs/queries.md](docs/queries.md).

## What the tests enforce

- **Metadata:** UUID id, ATT&CK tactic + technique tags, level, status, false positives documented, references
- **True positives:** each rule must fire on every event in its fixture's `tp` list, including evasions like renamed binaries (rclone via `OriginalFileName`, rundll32 via ordinal `#24`)
- **False positives:** each rule must stay quiet on realistic look-alikes: `vssadmin list shadows`, `7z x -p` (extracting, not archiving), `rclone --dry-run`, failed `StopLogging` calls, a newsletter inbox rule
- **Conversion:** every rule must convert cleanly to each target SIEM
- **Docs:** generated coverage and query docs must be current

The test suite was checked with deliberate mutations: weakening a rule's match list fails the true-positive test; removing a filter fails the false-positive test.

## Sample conversion

`proc_creation_win_lsass_dump_comsvcs.yml` becomes:

```kql
DeviceProcessEvents
| where (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")
    and ProcessCommandLine contains "comsvcs"
    and (ProcessCommandLine contains "minidump" or ProcessCommandLine contains "#24" or ProcessCommandLine contains "#+24")
```

## How to run

```bash
git clone https://github.com/fariselkhatib/detection-as-code.git
cd detection-as-code
pip install -r requirements.txt

python -m pytest -v         # validate + test + convert every rule
python -m dac.convert       # regenerate docs/queries.md
python -m dac.coverage      # regenerate docs/coverage.md
```

## Adding a rule

1. Write `rules/<platform>/<name>.yml` in Sigma format
2. Add `tests/fixtures/<name>.json` with `tp` and `fp` event lists (at least one each, more is better)
3. Run `python -m dac.convert && python -m dac.coverage && python -m pytest`
4. Open a PR. CI blocks the merge if anything fails

## Limitations

- **The test engine implements a Sigma subset** (`contains`, `startswith`, `endswith`, `re`, `all`, `exists`, and the full condition grammar). It raises an error on anything else rather than silently passing, so an unsupported modifier fails CI instead of producing a false green.
- **Fixtures are synthetic.** They prove the logic, not that your telemetry looks like this. Validate field names against your own data before deploying; Sysmon, Defender, and EDR exports differ.
- **Conversion targets are partial.** AWS and M365 rules convert to Splunk only; the KQL pipelines used here don't map those log sources. The 7045 rule has no Sentinel conversion for the same reason.
- **pySigma versions are pinned** because backend compatibility breaks across minor releases. Upgrade deliberately and let CI tell you what changed.
- **No tuning data.** False-positive notes come from experience, not measured alert volume. Run new rules in a hunting or test status before alerting.

## License

MIT. See [LICENSE](LICENSE).
