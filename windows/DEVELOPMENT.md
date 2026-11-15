# Implementation and verification plan

1. Review every Windows script, Sysmon XML, repository README, playbook and CI.
2. Share event normalization/detection and oldest-first collection between GUI and
   console. Persist JSONL before advancing record checkpoints; report source errors,
   rollover/reset and backlog. Keep network snapshots separate from event history.
3. Move queries off the GUI thread; retain collection during pause/filter; provide
   searchable recent history, GUID process relationships and source/Defender health.
4. Stage one immutable repository revision, validate all payload hashes and syntax,
   protect local code/evidence, back up audit settings, preserve existing Sysmon,
   retain previous versions/evidence, and report partial installation accurately.
5. Add portable regression checks and Windows PowerShell 5.1 CI. Add an explicit,
   isolated-lab integration harness and manual GUI/resource/WinRM checklist.
6. Run available checks, then inspect Windows VM capabilities. Record actual results
   and blocked tests; open a draft PR without merging if Server testing is blocked.

Response safety: monitoring never initiates containment. The later operator-requested
firewall panel adds only manually approved scoped rules, protected-service/address
checks, pre-change recovery records and exact-name undo. No automated account,
service, quarantine or host-isolation actions are implemented. Defender remains
independent. See README for approval and recovery requirements.

Expanded scope completed after operator feedback: direct process/socket and persistence
observations independent of Event Logs; immutable 15-minute scoped registry and
60-second account baselines; context-sensitive WinRM leads; optional focused Testimo
adapter; novice triage view; independent design and validation subagent reviews;
benign CCDC behavior rehearsal in disposable Server 2022 CI.
