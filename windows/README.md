# CCDC Windows Blue Team — one-command installer

A **free Windows Server 2019/2022 visibility-first EDR-style monitor** for authorized CCDC blue-team use. Built around short-lived process execution, parent-child process relationships, PowerShell command content, and network connections. No Linux server or paid account required. GUI requires Windows Server **Desktop Experience**; Server Core can run the console watcher.

## Install + run (one command)

Open **Windows PowerShell 5.1 as Administrator** on each Windows competition server:

```powershell
irm https://raw.githubusercontent.com/TateWilson1/Security-Toolkit/main/windows/Install.ps1 | iex
```

This command runs code downloaded from GitHub **as Administrator**. Review [Install.ps1](Install.ps1) before running it. Competition proxy/firewall must allow `raw.githubusercontent.com` and `download.sysinternals.com`; otherwise pre-stage the scripts and signed Sysmon package according to event rules. No code is uploaded to an external service.

The installer downloads all project files, saves a pre-change baseline, enables Windows process/account/logon and PowerShell auditing, downloads **Microsoft-signed Sysmon** from Sysinternals, installs/configures it for process and connection events, adds a **CCDC Blue Team** desktop shortcut, and opens [Dashboard.ps1](Dashboard.ps1). It fails loudly if Sysmon setup fails rather than silently reporting full coverage.

## The GUI

- **Process + Connection Events** — stream new Sysmon Event 1/3/5, Security login/account events, and PowerShell 4104. Shows exact time, process, parent, IPs, user, priority; click a row for command and full forensic details.
- **Live TCP Sessions** — updates connected endpoints, owning process name and PID every 2 seconds.
- **Scoring Safety** — prior scoring dependencies, what to confirm before taking disruptive action.
- **One-click controls** — Save baseline, Check services, Export evidence, Defender status, Pause view, Alerts only.

`REVIEW` and `HIGH` are heuristic leads, **not proof of compromise**. Some authenticated PowerShell through WinRM is legitimately required by CCDC scoring. Sysmon captures process launches even when the process exits before the live TCP view refreshes. This is event monitoring, *not full packet capture*; high event volume can exceed the dashboard's per-poll display window. Use original Event Logs and evidence exports for complete review.

## Detection vs. prevention

This is **not a full managed EDR**. The dashboard **never** auto-blocks an IP, kills a process, disables a user, isolates a host, changes GPO, or modifies the firewall. Microsoft Defender Antivirus, **if real-time protection is enabled**, performs its own malware detection and quarantine. Check Defender status in the dashboard. Custom-made Red Team activity may not be classified as malware, even if its process and network behavior is visible.

**Why no automatic account/network blocking?** Scoring tests may remotely authenticate to WinRM, SMB, SQL, RDP, and DNS depending on the host, and falsely quarantining scored services can cost competition points. Build verified response rules only after learning the *current* competition's scoring addresses and accounts.

## Console helper

Scripts are installed to `C:\ProgramData\CCDC-BlueTeam`. Open elevated PowerShell:

```powershell
cd $env:ProgramData\CCDC-BlueTeam
.\CCDC-BlueTeam.ps1 -Mode Baseline -Role AD
.\CCDC-BlueTeam.ps1 -Mode Check -Role AD
.\CCDC-BlueTeam.ps1 -Mode Watch -Role AD
.\CCDC-BlueTeam.ps1 -Mode Export -Role AD
```

Replace `-Role AD` with `-Role MSSQL` for SQL Server or `Other` for generic Windows. The installer detects AD and MSSQL roles automatically for initial setup. Event and baseline evidence is written under `C:\ProgramData\CCDC-BlueTeam\Evidence`; protect it because logs can include command-line secrets.

Review the [full playbook](CCDC-Playbook.md) for Windows service validation, account changes, incident capture, rollback planning, and anti-scoring-breakage guidance.

## Known limitations and testing

The PowerShell files require Windows PowerShell 5.1, Administrator permissions, and Sysmon supported by the target Windows build. Signed Sysmon is free Microsoft software, **not open source**. Sysmon's network logging is intentionally broad and can generate many events on a busy DC. Dashboard UI is intended for Desktop Experience, not Server Core. Windows Server deployment and competition proxy behavior **must be rehearsed in an isolated VM**; scripts have not been executed on a live competition server as part of this GitHub change.
