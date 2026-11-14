# Verification record

Development host: Linux x86_64, November 14, 2026. Portable checks use PowerShell
7.4.6; this **does not establish Windows PowerShell 5.1 or Server runtime support**.

## Available checks

```powershell
./windows/tests/Update-Manifest.ps1 # after any payload edit, commit updated manifest
./windows/tests/Test-Static.ps1
./windows/tests/Test-Monitoring.ps1
```

Portable regression suite exercises XML escaping, process/parent GUIDs and PIDs,
Security NewProcessId mapping, timestamp precision, IPv6 endpoints, script fragments,
known management authentication, WinRM review severity, maximum severity, oldest-first
601-record bursts, empty re-poll, checkpoint reload, durable history bounds, source
failure, log reset, failed append and invalid profile handling using module-scoped
fake sources. These tests do not call real Windows Event Log APIs.

GitHub Actions `ccdc-verify.yml` runs static and unit checks with **Windows PowerShell
5.1 on windows-2022**. Its dependent integration job uses a disposable Server 2022
runner to invoke the real installer twice (pinned to the pushed commit), install
signed Sysmon, generate benign process/network activity, collect actual events,
start/restart WinForms, export EVTX and sample resources. Artifacts retain logs,
JSON outcomes, screenshots and OS identification, even on failure. Do not infer a
pass from the existence of this workflow: consult the actual run and artifacts.

## Isolated VM execution

On an explicitly disposable **fresh Server 2022 Desktop Experience** VM, from an
Administrator Windows PowerShell prompt in a checkout of the PR:

```powershell
./windows/tests/Test-WindowsIntegration.ps1 -Revision <PR-commit-SHA> -AllowLabChanges -ResultsDirectory C:\Lab\ccdc-results
```

The harness refuses to remove an existing install and requires lab-change opt-in.
It enables logging and installs Sysmon. It does not uninstall/revert the VM; discard
only your own disposable lab after collecting results. A failed localhost Sysmon
network test distinguishes successful socket creation from missing event coverage.
It must not be reclassified as complete network capture.

## Required operator acceptance / infrastructure gaps

- Repeat on **Server 2019**, including missing/disabled Sysmon, stopped service,
  tampered/unavailable downloads, corrupt checkpoint, partial export, Server Core,
  failure after auditing and existing third-party Sysmon rules.
- Interactively inspect layout, resize/minimum-size handling, keyboard navigation,
  details/search/alerts, process relationships, pause/resume and export visibility.
  Automated screenshot/startup is only partial GUI testing.
- In an isolated domain lab, test WinRM from a second approved Windows host with
  the source address in the profile. Confirm AUTH, wsmprovhost/PowerShell context,
  and absence of destructive response. Never test against external infrastructure.
- Run at least a 60-minute busy-DC soak with realistic event rates. Record CPU,
  working set, handles, backlog, disk growth and rollover; the 30-second CI sample
  is not sufficient capacity testing. Compare remote DNS/AD/WinRM/SMB/SQL/RDP/web
  checks before/after; local listeners do not prove scoring authentication/content.
- Reboot/restart, verify history/cursor continuation and shortcut elevation.
  Capture full journal/export hashes and timestamp comparisons against the VM clock.

No access to the user's VMware Workstation host has been granted or used. A local
VMware rehearsal requires the user to provide an explicitly disposable VM and an
approved connection (e.g. reachable WinRM/RDP from this environment or a supported
Windows desktop session). Do not alter any existing VM. A connected Linux cloud
desktop is not access to the user's Windows computer.

Actual run outcomes and outstanding failures are recorded below after execution.

## Additional scope from operator feedback

`Test-DirectState.ps1` uses synthetic live-state snapshots to verify behavior alerts
for SYSTEM-owned SQL children, persistence differences without Event Logs, sensor
changes, PID reuse, independent journaling and preservation of state on failed queries.
Windows CI runs this alongside the original collector suite. Additional real-VM
checks validate native direct snapshots; domain/Testimo execution needs a domain lab.
The uploaded packet is local reference material and is not committed to this public PR.
