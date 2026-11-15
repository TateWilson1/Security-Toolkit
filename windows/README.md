# CCDC Windows monitoring

Native Windows PowerShell 5.1 / WinForms monitoring for **x64 Server 2022 and
2019** (Desktop Experience for the GUI). Monitoring never triggers automatic
containment. Optional manual firewall controls require explicit approval; no
account changes, process termination or toolkit file quarantine are performed.
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
| Block IP/port | Manual scoped firewall panel, explicit approval, recovery record and undo | Recheck scoring; no automatic expiration or blocking |
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

## CCDC operation when credentials or logs cannot be trusted

No username, SYSTEM identity, service identity, signed binary, or known management
address is a blanket trust exemption. Behavior rules also apply to direct live
process observations. The toolkit now samples CIM process state and TCP sockets
roughly every 5 seconds, retaining first-seen observations and no-longer-observed
processes in the same journal, separately labeled from recorded creation/exit
**events**. Creation time + PID distinguishes sampled lifetimes. Parent attribution
is omitted if PID reuse makes the current parent inconsistent with the child's age.

Every ~30 seconds it compares scheduled task actions/principals, service executable/
identity/start mode, and HKLM Run/RunOnce/Winlogon values against the previous
successful snapshot. The first successful state is retained as a baseline, not
asserted clean. Failed queries preserve the last successful comparison state;
missing data never invents process exits or persistence deletions. It also observes
Sysmon service status, logging registry settings and Defender real-time state;
sensor changes produce an investigation alert. Changes can be legitimate teammate
work. These are direct state checks and do not require Event Logs to report changes.

Snapshots miss transient activity between observations, and do not enumerate all
user hives, WMI persistence, kernel objects or process injection. A short connection
that opens/closes between samples needs event telemetry. An attacker with sufficient
privilege can tamper with Event Logs **and** CIM/process APIs/toolkit/evidence. An
approved independent collector or packet capture on allowed infrastructure can add
an independent viewpoint; this version does not ship an off-host collector. Source
health warnings remain visible even when there are no red findings.

**Evil-WinRM:** WinRM Operational records, logon events, wsmprovhost/PowerShell
ancestry, child utilities, script patterns and network behavior provide server-side
leads. The default profile includes several remote-tool/loading content patterns.
Names can be changed and encrypted/in-memory actions may have no visible script
text. Server telemetry generally cannot prove which WinRM client connected;
ordinary WinRM activity is not labeled confirmed Evil-WinRM. Correlate with known
team actions and scored PowerShell sessions. No new WinRM service configuration or
network capture is enabled by adding the channel.

## Easy triage and Testimo

The opening **START HERE** tab puts red **Investigate first** items ahead of amber
**Review** items. Selecting one explains what happened, why it matched, which
account ran it and what to check next. Green means **No rule matched**, never a
verified safe process. Coverage warnings have their own prominent indicator.
Advanced tabs retain full fields and source identity for an experienced teammate.

**Active Directory** has an on-demand read-only overview and a focused optional
[Testimo](https://github.com/EvotecIT/Testimo) assessment. The overview reads current
AD membership, account flags and password policy, without depending on local logs.
Testimo integration uses its documented `Get-TestimoSources` / `Invoke-Testimo`
interfaces, explicitly selects DomainPasswordComplexity and DomainKerberosAccountAge,
scopes to the current domain, saves version/scope/results and opens a local embedded
HTML report. It does not run Testimo's broad default suite or enable remediation.
Testimo's own skipped/absent results are **not** considered passes.

Testimo and Microsoft's ActiveDirectory/RSAT module must already be available.
Review/pin Testimo and its dependencies in the lab; stage them publicly/offline as
allowed by the packet. An operator may explicitly install a reviewed version with
`Install-Module Testimo -RequiredVersion <reviewed-version> -Scope AllUsers`; this
is an optional dependency, not part of the one-command monitoring install. Module
import and report execution are still unverified on a real AD domain in this PR.
A basic standalone Server runner cannot validate domain assessments.

## Packet-derived safeguards

The supplied 2026 MWCCDC Invitational packet confirms authenticated WinRM commands,
DNS resolution, SQL queries, SMB required-file access, RDP authentication, Splunk
queries/management and HTTP content checks. The profile represents service types
without team addresses or passwords. Its packet-inspired examples are not authority
for another competition: the current team portal/injects determine scored services.

Packet rules also call for generally reachable public services (no scorer-only
allowlists), preserved ICMP and assigned names/addresses, free/open-source tools
without trials, no workstation repurposing, and no competition snapshot reversion.
These reinforce passive monitoring defaults and approved, reversible response. The lab
harness is for disposable test VMs, not the competition NETLAB environment. Do not
publish team packets, credentials or private event-specific profiles; keep them out
of source control. Follow the event's software/staging and outside-assistance rules.

## First registry baseline and competition account additions

The first successful snapshot of each configured registry scope is retained under
`Evidence\Telemetry\baseline-*.json` and never replaced on restart/reinstall.
The GUI and Watch compare those scopes every **15 minutes** while collection is
running. Each change includes initial baseline, prior sample and new value; repeated
unchanged drift does not create repeated alerts. A return to the original value is
also recorded. Failed/unreadable scopes report coverage errors and preserve their
last successful state. This is value/key comparison, not a registry restore tool.

Default scopes recursively cover HKLM Run/RunOnce, Winlogon, PowerShell policy,
Image File Execution Options, and LSA root values. Protected LSA subkeys are
explicitly excluded from the default scope; RegistryValueOnlyPaths controls which
configured roots omit recursion. This is **not a complete registry hive backup**:
loaded user hives, unrelated application keys and protected unreadable areas may be
outside coverage. Add `RegistryPaths` (an array of registry-provider paths) to the
profile to choose explicit scopes; each scope is capped at 10000 keys and fails
visibly rather than silently truncating. Windows ACLs continue to govern reads.
Service/task/HKLM startup snapshots also provide more frequent focused comparison.

Local account SIDs are sampled every **60 seconds**; on domain-joined machines the
current domain's user objects are queried through paged LDAP with timeouts. Domain
controllers use the domain directory rather than pretending they have a normal
local SAM. Each successful scope gets an immutable starting account list. A newly
observed SID, including a service account, produces an amber review finding even
without Event 4720. Account property changes and removals are recorded too. Normal
Security account events still arrive between samples when auditing is available.
A user created and deleted between samples can be missed if event telemetry is
unavailable. A failed domain bind is a coverage warning, not an all-clear result.
The tool never creates, enables, disables or removes competition accounts; only
the explicitly opted-in disposable integration harness creates its own disabled
lab user and removes it afterward.

## Simple Windows Firewall controls (2019 / 2022)

The **Firewall controls** tab offers service presets, Allow/Block, TCP/UDP/Both,
explicit ports, remote IP, direction and Windows network profile. Examples:

- **Allow DNS** selects port 53 and creates both TCP and UDP rules after approval.
- **Block SSH** selects TCP 22; choose Any remote address or one identified IP.
- **Block one IP** uses the Specific IP preset and TCP/UDP, or limits that address
  to explicit ports. It does not silently disable ICMP or change a profile default.

Every change has a review/confirmation dialog and a recovery record saved before
mutation in `Evidence\Firewall`. The GUI applies it in the background and reports
success/failure inline. Undo removes one selected toolkit rule; both-transport
changes have two named rules, so undo each if needed. Existing Windows/GPO rules
are displayed through their profile status but are not bulk edited/reset. The rule
list is limited to the first 100 toolkit-created rules. Each toolkit rule has its
exact unique name in the recovery record.

Broad blocking of a protected/scored port is refused. On detected domain controllers,
AD authentication/directory/RPC ports are protected too, including dynamic RPC
ports 49152 and above. A specific attacker IP can be scoped after explicit scoring
risk acknowledgement; management/scoring addresses in the profile cannot be blocked
through this control. Own-host/loopback and invalid targets are rejected. There is
no global block-all, disable-firewall or reset button. If the profile omits a required
service, the software cannot infer that event's scoring dependencies: verify it first.

These are native **NetSecurity** rules, not Palo Alto ordered policies. Windows
explicit block rules take precedence over allow rules. Adding Allow DNS cannot
cancel an existing explicit DNS block; centralized GPO can also prevent local rules
from taking effect. Verify the live scoring portal and remote authenticated service
access after each change. This version does not claim a local rule proves effective
network reachability or automatically remove rules after a timer.
