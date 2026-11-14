# CCDC Windows monitoring

Native Windows PowerShell 5.1 / WinForms monitoring for **x64 Server 2022 and
2019** (Desktop Experience for the GUI). Detection only: no account changes,
firewall changes, process termination, file quarantine or automatic containment.
Defender Antivirus operates independently. Runtime verification status is in
[TESTING.md](TESTING.md); rehearse before using this on scored infrastructure.

## Install

Open **64-bit Windows PowerShell as Administrator**:

```powershell
irm https://raw.githubusercontent.com/TateWilson1/Security-Toolkit/main/windows/Install.ps1 | iex
```

This executes administrator code from GitHub. Review/download it first when
possible. The bootstrap resolves main to one commit, downloads that revision's
payload, checks every file against its SHA256 manifest, parses scripts and
validates XML/profile before configuration changes. Hashes protect payload
consistency, **not against a compromised repository or bootstrap**. For a reviewed
revision, download its installer and run `./Install.ps1 -Revision <40-character-SHA>`.
Allow `api.github.com`, `raw.githubusercontent.com`, `download.sysinternals.com`
and Windows certificate validation endpoints. Do not disable signature verification
if an offline lab cannot validate Microsoft Sysmon.

The installer protects `C:\ProgramData\CCDC-BlueTeam`, logs installation there,
backs up audit policy and the exact registry values it changes, captures an inventory,
enables auditing/script block logging, and installs signed Microsoft Sysmon if
missing. **Existing Sysmon configurations are preserved**: verify their events
1/3/5 coverage yourself. A text `sysmon -c` dump is not a restorable XML backup.
Changing an existing deployment requires retaining its original XML and explicitly
running helper Sysmon mode with `-ReplaceSysmonConfig`. Existing stopped services
cause an incomplete installation rather than being silently started/reconfigured.

Validated versions are installed under `Versions`; the desktop shortcut points to
the activated version. Reinstall retains evidence, profile and previous versions.
Installer failures report INCOMPLETE; settings already applied are not silently
rolled back. Server Core can collect with console Watch; GUI startup is incomplete
there. `-NoLaunch` installs without launching; `-Diagnostic` reports OS, channels,
Sysmon and Defender without enabling logging (it still creates/protects the log
folder). Never run the installer concurrently with another installation.

## Dashboard

- **Timeline:** process creation/exit, Sysmon connections, authentication, account,
  service/task and available persistence events; select for full JSON details,
  original channel/record identity, command, user, PID, GUID and parent information.
- **Search / Alerts only:** filter the recent 1200 retained events, including
  startup replay. Pause freezes the view while background collection continues.
- **Search archive:** scan all daily JSONL journals in the background, retaining the
  latest 1200 matches. Literal matching searches JSON text (backslashes are escaped);
  double click a result for details. Collection resumes after the scan, so very
  large archives can increase backlog.
- **Process relationships:** GUID-linked creations from the retained view; double
  click for full details. Parents outside that view remain explicit. A process with
  the same PID in a different lifetime is not silently attached to an old parent.
- **Live TCP:** current socket snapshot, all states, capped at 2000 displayed rows;
  IPv6-safe endpoints, PID and best-effort process names. A PID can exit/reuse
  between snapshot and name lookup. This is separate from historical event records.
- **Sources + Defender:** missing/disabled/error sources, backlog/retention gaps and
  cached Defender protection status (refreshed about every 30 seconds). An enabled
  Sysmon channel proves neither a running service nor that its rules emit all events.
- **Export evidence:** native EVTX for the selected recent interval, JSONL history,
  per-channel outcome and SHA256 manifest. Partial exports are explicitly reported.
  Baseline/service checks open a short-lived helper window. Defender status stays
  in the dashboard.

Queries and evidence writes run in a dedicated runspace. Each batch reads up to
250 **oldest** matching records per source and saves JSONL before checkpoints.
Initial collection starts at the oldest retained log record; large Security logs
can take time to drain. New records remain queued in Windows Event Logs, subject
to retention. A channel failure does not advance its cursor. Checkpoints resume
collection across application restarts. Collection runs while GUI or console
Watch is running; it is not a persistent Windows service. A lock prevents two
collectors from corrupting checkpoints; run one GUI or Watch per data directory.

Crash recovery can replay a committed row if the checkpoint was not yet saved;
`Key` (channel, record ID, timestamp) supports deduplication. GUI deduplicates its
retained window. Security 4688 and Sysmon 1 are independent observations and are
labeled by source, not two guaranteed distinct process launches. UTC timestamps
are retained with source precision; timeline renders local time. Script block
fragments retain message-number and total fields rather than claiming reconstruction.

## Profile and detection

Edit `C:\ProgramData\CCDC-BlueTeam\profile.json` (retained across updates), then
restart. Or launch `Dashboard.ps1 -ProfilePath C:\Lab\current-packet.json`.
Start with [profile.default.json](profile.default.json). It contains **no prior
competition addresses**. KnownManagementAddresses uses exact IP strings and only
reduces unknown-source authentication alerts; it does not suppress other rules.
Rules have ID, Enabled, Kinds, Field, regex Pattern, Severity and Description.
Supported severities: INFO, REVIEW, HIGH. Highest matching severity wins; regexes
have a 100 ms timeout. Malformed rules stop loading and report the error.

Remote WinRM/WMI ancestry is REVIEW, not proof of compromise. Benign script blocks
are INFO unless a configured rule matches. Web/SQL child processes are a heuristic
HIGH lead requiring application context. Account/group/task/service changes are
review leads, not a claim every group is administrative. Alerts do not trigger
response. RequiredPorts, ProtectedServices and ServerRole are packet metadata for
operators/future response work; they currently do not enforce policy or alter
service checks. Default helper checks are advisory examples, not live scoring.

## Console / evidence

```powershell
$root = "$env:ProgramData\CCDC-BlueTeam"
$version = (Get-Content "$root\current-version.txt" -Raw).Trim()
& "$version\CCDC-BlueTeam.ps1" -Mode Watch -OutputDir "$root\Evidence" -ProfilePath "$root\profile.json"
& "$version\CCDC-BlueTeam.ps1" -Mode Export -OutputDir "$root\Evidence" -ExportMinutes 60
& "$version\CCDC-BlueTeam.ps1" -Mode Check -Role AD
```

Daily UTF-8 JSONL is under `Evidence\Telemetry`. To search all historical records:

```powershell
Get-ChildItem "$root\Evidence\Telemetry\events-*.jsonl" |
  ForEach-Object { Get-Content -LiteralPath $_.FullName } |
  ConvertFrom-Json | Where-Object CommandLine -like '*example*'
```

Evidence can contain credentials/script secrets. Installation restricts access to
Administrators and SYSTEM; control copies and exports similarly. No external
upload occurs. History grows without automatic deletion: monitor disk space,
archive to authorized storage, and size Windows logs through approved lab-tested
policy. Busy DCs need a soak test and appropriately tuned Sysmon rules.

## Troubleshooting and recovery

- **Incomplete install:** inspect `install-*.log`; use downloaded installer
  `-Diagnostic`; check download/TLS/certificate validation and administrative rights.
  Failed staging is retained for diagnosis. Fix the cause and rerun; evidence stays.
- **GUI absent:** Desktop Experience and full .NET/WinForms are required. Run the
  activated Dashboard.ps1 directly in elevated PowerShell to see startup errors.
- **No events:** inspect source health, enabled channels, audit/GPO settings and
  Sysmon rules; generate a benign process. An empty channel can be normal. Audit
  policy or script block policy from GPO can supersede local settings.
- **Slow GUI/backlog:** collection drains oldest first. Check Resources in Task
  Manager and log retention; tune rules after a lab test. Search and trees cover
  the recent window, not all archived records. Full history load on startup scans
  the journals with bounded memory and can take time for large archives.
- **Collector lock:** close other GUI/Watch instances. Locks release on process exit;
  do not delete checkpoints as a routine workaround. Corrupt checkpoints report an
  error. Save them before deliberately replaying retained logs.
- **Logging rollback:** locate `Evidence\preinstall-*`. Review `registry-values.json`:
  restore each saved value, or remove **only that named value** if Exists was false.
  `auditpol /restore /file:<backup audit-policy.csv>` restores the whole saved audit
  policy: coordinate first because it also reverts subsequent legitimate changes.
  Recheck effective GPO and scoring. Baseline inventory operations may have warnings;
  the installer does not claim every optional AD module/inventory succeeded.
- **Toolkit rollback:** close GUI, point the shortcut back to the retained previous
  version, keep the same external Evidence/profile. New installation does not remove
  old versions. Uninstalling toolkit does not require disabling scored services;
  Sysmon uninstall and audit rollback are separate reviewed changes.

## Response options / future work

| Action | Current behavior | Requirement before implementation |
|---|---|---|
| Kill process | No action | Explicit approval for a GUID + current PID lifetime, evidence first, protected-service checks |
| Block IP | No action | Explicit address/port-scoped approval, expiring rule, removal command, verify scoring |
| Quarantine file | No toolkit quarantine | Copy/hash/ACL-protected manifest, original path/ACL and restore verification; avoid service binaries |
| Persistence response | Record supported events | Export original task/service/registry state, exact approved change and recovery |
| Defender | Show status; AV handles its own policy | Use native Defender quarantine and `MpCmdRun -Restore -ListAll` / approved restore workflow |
| Automated policies | Disabled; no execution engine | Separate opt-in per rule, current packet profile, approval record and dry-run; never auto-isolate a DC or disrupt a scored service |

This is not a managed EDR, guaranteed malware prevention, packet capture, or
complete behavioral sensor. Sysmon may omit loopback/short connections, filtered
activity, or events lost to disabled/tampered sources/retention. Local log-clear
recognition detects record counters moving backward; a clear followed by enough
new records to exceed the saved counter may not be detected. Script block logging
can be bypassed and native actions may not expose command content. Sysmon is free
Microsoft software, **not open source**. See the [playbook](CCDC-Playbook.md) for
operator context; prior packet details are historical, never a current profile.
