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

Response safety: detection only. No firewall, account, service, quarantine or host
isolation actions. Defender remains independent. Future responses require a separate
reviewed implementation; see README for approval and recovery requirements.
