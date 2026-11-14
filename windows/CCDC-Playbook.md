# CCDC Windows/AD Blue Team - Next Competition Playbook

**Prepared from November 14, 2026 Invitational lessons.** This is an operational checklist and an optional Windows Server 2019/2022 PowerShell helper. **It is a template, not an assertion that the next competition uses the same systems, credentials, IPs, or scoring checks.** Replace the table with the NEW packet and live Team Portal/ISE/NISE scoring screen.

## The governing rule

**Availability + scoring first; visibility second; hardening third.** Never change something you cannot test or roll back. A local service check is not equivalent to authenticated scoring. Preserve screenshot/evidence before/after each change.

2026 Invitational packet-specific restrictions: keep public services broadly reachable (no scorer-IP-only allowlist); no hostname/IP/VLAN changes without an inject; keep ICMP on hosts; no free trials (free or open-source software only); no extra competition systems; workstations cannot be repurposed as servers; no VM snapshot/scrub rollback; active blocking at the team's own scoring risk; unauthorized offensive scans of others are prohibited. Refer to the new packet for any changes.

## Prior environment reference (November 14 only)

| Role | Internal IP | Scoring requirements to preserve |
|---|---|---|
| AD / DNS (Server 2022) | 172.20.240.100 | DNS and authenticated WinRM commands on 5985 (verify configured port) |
| MSSQL (Server 2019) | 172.20.240.120 | SQL 1433 with login/query, SMB 445 with data, RDP 3389 with login |
| Debian Splunk | 172.20.240.20 | Splunk query and management 8089 |
| Rocky Linux web | 172.20.240.10 | HTTP/HTTPS expected content |
| Ubuntu mail | 172.20.240.15 | Mail protocols / content depending on portal |
| Palo Alto inside/gateway | 172.20.240.254 | Internal routing/firewall; do not randomly deny scoring |

Prior AD domain was `underpressure.local`, and internal subnet was `172.20.240.0/24`. Do not carry these into a new event without verification.

## Before event day: prepare an **offline-accessible** kit

- Download and test **System Informer** (live graphical processes and Network tab), **Sysmon** (Microsoft, free; events 1/3/5), **Autoruns** (persistence comparison), **Testimo** (AD audit), and **BLUESPAWN** only for optional hunt/audit mode. Prefer Windows Defender already on Windows Server for malware quarantine. Use the official download sources and verify signatures/hashes.
- Bring this folder (`CCDC-BlueTeam.ps1`, `ccdc-sysmon.xml`, this playbook). Confirm allowed distribution/staging under the *new* event rules. A previous event limited proxy access and required advance registration of team GitHub repositories.
- Rehearse in a disposable Windows Server 2022 + Server 2019 lab: baseline; install Sysmon; run watcher; create benign PowerShell command, connection, and scheduled task; verify events; then restore lab.
- Make a simple shared service status board: **host, service, current score, last change, responsible teammate, rollback, retest result**.
- Designate one **Windows change owner**, one **scoring checker**, one **SOC/monitor operator**, and one **network/firewall owner**. Nobody makes concurrent uncoordinated policy changes.
- For a future full SOC GUI, **Wazuh + Sysmon** is the open-source path, but only where a manager/dashboard can run on allowed infrastructure without repurposing workstations or sacrificing scored services. **Do not add a forbidden VM**.

## First 10 minutes after competition access

1. Read new team packet + topology + live scoring portal. Write the *actual* scored services, source requirements, and assigned IPs. Screenshot baseline score.
2. Confirm server names/IPs/routes without changing any settings. Capture `ipconfig /all`, `Get-NetRoute`, firewall, service status, listening ports, users/group membership, process list, scheduled tasks.
3. Run the read-only **Baseline** mode on AD and MSSQL. It saves CSVs and a firewall configuration export to `C:\CCDC`. Copy evidence to an allowed shared location, if permitted.
4. Run **Check** locally on each Windows server. On AD additionally verify `Resolve-DnsName <domain> -Server 127.0.0.1`, `Test-WSMan localhost`, and relevant services. On MSSQL confirm SQL service, content/authentication, SMB SOPs and RDP from a separate authorized workstation.
5. Compare the checks to the **live scoring portal**. Open an incident note for any service already down: do not attribute all outages to the Red Team.

## Next 10-20 minutes: turn on visibility, with test-after-change

1. Run `-Mode Logging` on each Windows server, or use a **computer GPO scoped only to the intended server OU**. It enables process creation auditing (4688 + command line), authentication/user/group events, PowerShell script block logging (4104). Command lines may contain secrets: protect logs.
2. Install official Sysmon with the included XML (Event 1 process start; 3 TCP/UDP connection; 5 exit). On an extremely busy AD host, tune Sysmon network noise before leaving it on for the whole event.
3. Start `-Mode Watch` in an elevated, separate PowerShell window. It displays newly recorded process/network/authentication events, with high-signal patterns highlighted, and a current TCP connection poll. Full event data goes to a local CSV. Run System Informer alongside it for a clearer GUI.
4. Confirm the score after logging and Sysmon deployment. Logging is normally passive, but installing drivers and increasing telemetry still requires supervision.

## First controlled hardening pass (one change -> test score)

- AD: list **Domain Admins** recursively; export users and groups; identify unknown, stale, or compromised privileged access using evidence. Rotate verified compromised credentials only after understanding dependencies and the expected scoring path. **Do not bulk-disable accounts or remove unknown 'scoring' accounts**. In the prior event, the scoring service selected among AD users and an authenticated local WinRM check still did not prove remote scoring succeeded.
- AD: inspect `PasswordNotRequired`, `DoesNotRequirePreAuth`, `PasswordNeverExpires`, MachineAccountQuota, vulnerable GPOs, and unexpected delegation. Fix *targeted* findings and document changes. Disabled Guest should generally remain disabled; never enable Guest just to assign a password.
- AD: do not disable WinRM/5985, DNS/53, domain services, or ICMP if they're required. A legitimate WinRM score test may launch PowerShell through `wsmprovhost.exe`.
- MSSQL: keep 1433/445/3389 and login/queries/data functioning; verify `MSSQLSERVER`, `TermService`, `LanmanServer`. **Do not apply HardeningKitty HailMary/repair in bulk.** Use audits as a to-do list. Avoid disabling Windows rules in bulk.
- Network/DNS: AD should use its authoritative domain DNS correctly. Troubleshoot external DNS separately at the DNS forwarder and Palo Alto; the prior event had upstream 1.1.1.1 timeout and the firewall dropping external DNS traffic. Do not point the domain controller's NIC at public DNS as a generic fix.
- Web: distinguish the scored Rocky Linux HTTP/HTTPS site from IIS on the AD machine. Do not disable a service just because it appears unscored in the packet; the **live portal** and injects control requirements. If a score drops, review last change first.
- Recovery: before rebooting/altering BCD, preserve console and diagnostic evidence. NETLAB/Proxmox consoles can power-cycle a stuck VM, but the Invitational rules expressly disallowed snapshot rollback; get White Team guidance for unexpected recovery problems.

## Detection logic and triage

All of these can be legitimate. They are **suspicious leads**, not automatic proof of a Red Team shell:

| Activity | Correlation / evidence |
|---|---|
| Remote WinRM shell | Security 4624 logon type 3 + Sysmon process `wsmprovhost.exe` -> `powershell.exe`/`cmd.exe` + PowerShell 4104 + source IP/time |
| Remote RDP | 4624 logon type 10 + RDP session logs + current 3389 connection |
| SQL command execution | Sysmon `sqlservr.exe` -> `cmd.exe`/`powershell.exe` (high signal); SQL logs + server process tree |
| Web shell | Web service worker (`w3wp.exe`, `httpd`, etc.) -> shell/script; web request logs + child process. For Linux use audit/journald or service logs |
| Persistence | New scheduled task, service executable path, Run/RunOnce key, WMI subscription, unexpected account/group changes |
| Privilege changes | Security 4720/4722/4725/4728/4732/4738, AD group membership diff, logon source/time |
| Network C2 | Sysmon 3 by process + remote address/port + repeated connections + process parent/command line |

**Response ladder**: alert -> correlate user/source/parent process -> compare with scoring baseline -> save event IDs/screenshots/export -> verify maliciousness -> apply a **narrow reversible** response -> retest scored functions -> submit incident report. Keep automatic IP blocks, host isolation, process termination, and AD account disabling **off by default** on scored servers. If you build Wazuh active response later, allow only *high-confidence*, time-limited actions tested against scorer behaviors in the lab; never block all 5985/53/1433/445/3389 or isolate the AD server automatically.

## When scores go down (DO THIS IN ORDER)

1. Note exact time/service/status and the last configuration change. Stop further hardening.
2. Verify local state: service running; TCP listener; Windows firewall rule; app authentication/content; DNS resolution. **Ping alone is not service validation**.
3. Verify from a separate authorized team VM; then check the portal. `Test-WSMan localhost` proves only local WinRM, not scoring credentials or remote access.
4. If the outage began right after your change, roll back that **specific** change, not every firewall rule/account/GPO on the domain.
5. If local and remote tests pass but scoring fails, inspect the actual service account/authorization and Team Portal status, then ask White Team through the proper channel if allowed. Do not guess that all disabled accounts should be enabled.
6. Create incident record: before/after, exact symptom, root cause status (confirmed vs suspected), changes, retest.

## Commands at a glance

```powershell
# On Windows Server, open an Administrator Windows PowerShell prompt.
cd C:\CCDC-Next-Competition

# Run on AD first; inventory does not change live configuration.
.\CCDC-BlueTeam.ps1 -Mode Baseline -Role AD
.\CCDC-BlueTeam.ps1 -Mode Check -Role AD

# Explicitly enable auditing, then install Sysmon (exe manually obtained from Microsoft):
.\CCDC-BlueTeam.ps1 -Mode Logging -Role AD
.\CCDC-BlueTeam.ps1 -Mode Sysmon -Role AD -SysmonExe C:\Tools\Sysmon64.exe

# Open another admin PowerShell window for continuous monitoring:
.\CCDC-BlueTeam.ps1 -Mode Watch -Role AD

# On MSSQL, repeat with -Role MSSQL; do not apply domain-wide policy.
.\CCDC-BlueTeam.ps1 -Mode Baseline -Role MSSQL
.\CCDC-BlueTeam.ps1 -Mode Check -Role MSSQL
.\CCDC-BlueTeam.ps1 -Mode Logging -Role MSSQL
.\CCDC-BlueTeam.ps1 -Mode Sysmon -Role MSSQL -SysmonExe C:\Tools\Sysmon64.exe
.\CCDC-BlueTeam.ps1 -Mode Watch -Role MSSQL

# Export last hour of relevant events for an incident report:
.\CCDC-BlueTeam.ps1 -Mode Export -Role AD -ExportMinutes 60
```

If the scripts were downloaded from the Internet, extract them to a local folder and inspect them before execution. `Unblock-File .\CCDC-BlueTeam.ps1` may be necessary; if execution policy is centrally enforced, follow the team's authorized approach instead of changing a domain-wide policy.

### Manual evidence and verification commands

```powershell
# AD (requires RSAT ActiveDirectory module and proper rights):
Get-ADDomain
Get-ADGroupMember 'Domain Admins' -Recursive | Select Name,SamAccountName,ObjectClass
Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,DoesNotRequirePreAuth |
  Select SamAccountName,Enabled,PasswordNeverExpires,PasswordNotRequired,DoesNotRequirePreAuth
Get-Service DNS,WinRM,NTDS,Netlogon
Test-WSMan localhost
# Replace domain name with domain discovered in NEW packet:
Resolve-DnsName underpressure.local -Server 127.0.0.1

dcdiag /test:dns

# MSSQL:
Get-Service MSSQLSERVER,TermService,LanmanServer
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 1433,445,3389

# Live established connections (sample, not all short-lived connections):
Get-NetTCPConnection -State Established |
  Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

# Defender status; Defender may already quarantine known malware:
Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled

# After each individual change:
.\CCDC-BlueTeam.ps1 -Mode Check -Role AD
# Also verify live scoring screen: the script cannot authenticate as the scorer.
```

## Lessons explicitly taken from November 14

- The internal DNS records worked but outside DNS forwarding failed; external DNS queries were being dropped at the firewall. **Separate internal DNS health from upstream egress.**
- Local WinRM authentication worked while the scoreboard remained down. **Authentication as the scorer matters**, and the scoring account may vary; do not assume process names/Domain Admin group members are all attackers.
- Bulk disabling AD users produced major uncertainty; changing service identities/permissions without accounting for scoring is dangerous.
- HardeningKitty's HailMary/partial execution risked the MSSQL service and account rights. **Use scan/audit mode and make targeted changes only.**
- IIS and firewall rules had to be restored after changes; keep exact rollback information, not a blanket reset.
- Reboots and boot recovery caused an outage; avoid risky late-stage reboot/hardening without backup/recovery path.
- You spent too much time digging through Event Viewer. **Start Sysmon + a live watcher/System Informer immediately**, then use CSV evidence for incidents and Wazuh only on permitted infrastructure.

## Limitations and safety

- `CCDC-BlueTeam.ps1` is a template, not tested on your competition's servers; **rehearse it in a lab**. The Watch mode polls events every 2 seconds and TCP state, and can miss short network connections without Sysmon or under exceptional event volume. Not all command content can be reconstructed (e.g. native program behavior, encrypted payloads, script logging bypasses).
- The watcher is a console alert view; System Informer provides the graphical live-process/network view. The **true centralized EDR GUI** upgrade is an approved Wazuh deployment.
- The Sysmon XML captures *all* ProcessCreate, NetworkConnect and ProcessTerminate events and may generate considerable load on a domain controller; reduce noise in a lab rather than disabling scored services.
- Event logging and CSV exports can contain plaintext secrets and sensitive user data. Restrict access and remove archives when permitted and no longer needed.
- The ZIP **does not contain a Sysmon executable**. Obtain it from Microsoft: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

## Official documentation

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon config: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files
- Process command-line auditing: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- PowerShell logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
- System Informer: https://github.com/winsiderss/systeminformer/releases
- Autoruns: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Wazuh: https://documentation.wazuh.com/current/quickstart.html