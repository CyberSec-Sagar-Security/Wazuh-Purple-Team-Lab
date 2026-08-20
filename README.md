# Wazuh Purple Team Detection Engineering Lab

![Status](https://img.shields.io/badge/status-active-success.svg)
![Platform](https://img.shields.io/badge/SIEM-Wazuh%20v4.14.5-blue.svg)
![Methodology](https://img.shields.io/badge/methodology-MITRE%20ATT%26CK-red.svg)

## TL;DR

A home-built purple team lab where I simulate real MITRE ATT&CK techniques against a monitored Windows endpoint, then measure — and fix — what a default Wazuh + Sysmon ruleset actually catches, misses, or gets wrong. First testing cycle covering 3 tactics surfaced three distinct, provable findings: a systemic false positive, a total detection blind spot, and a severity miscalibration on a real persistence technique. Each was closed with a custom-written, MITRE-mapped Wazuh rule — not just relabeled.

## Overview

Installing a SIEM is not the same as having working detection. Vendor and community rulesets ship with broad, generic logic that has to be validated against real technique execution before you can trust it — otherwise you don't know whether "no alerts" means "no attack" or "the rule doesn't work." This lab exists to demonstrate that validation loop end to end: simulate → observe → diagnose → fix → re-test → document, using the same MITRE ATT&CK-driven methodology real detection engineering and purple teams use.

## Problem Statement

- **Challenge**: Does Wazuh's default Sysmon-based ruleset actually detect real adversary technique execution, correctly, at the right severity — or just look like it does on a dashboard?
- **Impact**: An undetected technique is a blind spot a real attacker walks straight through. A real detection buried at Low severity is functionally the same as no detection, once alert volume is high enough that analysts triage by severity.
- **Constraints**: Single analyst, 3-VM home lab (VMware Workstation), free/open-source tooling only — no enterprise EDR, no unlimited compute, no vendor support.

## Technical Stack

- **SIEM / XDR**: Wazuh v4.14.5 (manager + indexer + dashboard)
- **Endpoint telemetry**: Sysmon (Windows), Wazuh agent (Windows 11 + Kali Linux)
- **Attack simulation**: Atomic Red Team (Invoke-AtomicRedTeam) — reproducible, MITRE ATT&CK technique-ID-mapped tests, not ad-hoc manual attacks
- **Detection authoring**: Wazuh rule XML (custom `local_rules.xml`), PCRE2 field matching
- **Framework**: MITRE ATT&CK (technique selection, coverage tracking, gap analysis)
- **Infrastructure**: VMware Workstation — Ubuntu 24 (Wazuh manager), Windows 11 (monitored endpoint), Kali Linux (secondary agent)

## Architecture

```
 [Windows 11 Endpoint] --Sysmon telemetry--> [Wazuh Manager - Ubuntu 24] --> [Wazuh Dashboard]
        ^
        |  Atomic Red Team executed locally
        |  (simulates post-compromise adversary behavior)

 [Kali Linux] --Wazuh agent--> [Wazuh Manager]
```

## Methodology: Test → Diagnose → Fix → Re-test

Every technique tested follows the same cycle: run a specific, MITRE-mapped Atomic Red Team test → check whether Wazuh's stock ruleset caught it, and at what severity → if it's wrong (missed, false-positived, or miscalibrated), write a scoped custom rule → re-run the same test to confirm the fix → document the before/after.

### Cycle 1 Results

| Tactic | Technique | Atomic Test | Stock Wazuh Result | Finding | Fix |
|---|---|---|---|---|---|
| Discovery | T1082 | System Information Discovery | **0 alerts** | Total blind spot — reconnaissance commands generated zero signal | Rule `100011`: new low-severity visibility rule |
| Execution | T1059.001 | PowerShell Fileless Script Execution | **18+ false "Critical" alerts** | Systemic false positive — PowerShell's own internal AppLocker self-check file misclassified as "Ingress Tool Transfer" (T1105 / Command & Control) on every single PowerShell launch | Rule `100010`: scoped suppression (only when creating process is genuinely `powershell.exe`/`pwsh.exe`) |
| Persistence | T1547.001 | Registry Run Key | 1 alert, but at **Level 6 (Low)** | Real persistence mechanism under-prioritized — a Run-key write is how attackers survive reboot, and it was scored the same as routine noise | Rule `100012`: escalated to **Level 12 (High)** |

Full custom ruleset: [`detections/local_rules.xml`](./detections/local_rules.xml)

### Example: closing the false-positive (Rule 100010)

```xml
<rule id="100010" level="0">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)PSScriptPolicyTest</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
  <description>FP suppression: PSScriptPolicyTest is PowerShell's own AppLocker
  self-test file, not malware — only when created by the legitimate binary</description>
  <mitre><id>T1105</id></mitre>
</rule>
```

Deliberately narrow: this rule only suppresses the alert when the file is created by the legitimate PowerShell binary. During testing, the same filename pattern was also created once by `sdiagnhost.exe` (Windows Diagnostics Host) — an anomalous creator process — and this rule correctly leaves that variant alerting, since an unexpected process writing this exact filename *is* worth a human look.

## What I Learned

- **Technical**: Wazuh rule XML — `if_sid` inheritance, AND-only logic across multiple `<field>` conditions, PCRE2 field matching, Sysmon Event ID semantics (1 = process creation, 11 = file creation, 13 = registry value set).
- **Security engineering**: A default ruleset's "MITRE ATT&CK coverage" claim and its *actual, validated* coverage are two different things — the only way to know which you have is to test it. False positives at scale are as damaging to a SOC as missed detections, because they train analysts to ignore Critical alerts.
- **A real mid-project correction**: initial guidance on the Atomic Red Team persistence test cited a stale/incorrect community reference for which registry key gets modified. Caught it by checking the actual raw Sysmon event data against what was claimed, not just trusting the source — exactly the kind of verification discipline this lab is meant to build.

## Real-World Application

This is the core loop of a Detection Engineer / Purple Team role: validate a detection ruleset against real technique execution, distinguish "no alert" (miss) from "wrong alert" (false positive) from "buried alert" (miscalibration), and close each with a scoped, documented fix rather than a blanket rule that trades one problem for alert fatigue. Directly relevant to SOC Analyst, Detection Engineer, and Security Engineer roles.

## Repository Structure

```
detections/   → Custom Wazuh rules (local_rules.xml), MITRE-tagged
reports/      → Full writeup per testing cycle
attacks/      → Atomic Red Team technique IDs run, exact commands, timestamps
metrics/      → Coverage tracking, before/after alert data
infra/        → Lab provisioning scripts (in progress — see below)
evidence/     → Key dashboard/terminal screenshots supporting each finding
```

## Future Enhancements

- [ ] MITRE ATT&CK Navigator coverage heatmap (before/after this cycle)
- [ ] One-command lab provisioning (Vagrant + Ansible) — current lab is manually built, which is itself a limitation worth fixing
- [ ] Wazuh Active Response automation with timeout-based auto-revert
- [ ] CI pipeline to lint/validate custom rule XML on every commit
- [ ] Expand technique coverage beyond the initial 3 tactics tested

## Lab Setup (current — manual)

Requires VMware Workstation/Player and 3 VMs: Ubuntu 24 (Wazuh manager, single-node install), Windows 11 (Wazuh agent + Sysmon), Kali Linux (Wazuh agent). Full setup walkthrough: see [`reports/`](./reports).

## Author

**Sagar Suryawanshi**
MSc Cybersecurity Student (Ireland) · AWS Certified Cloud Practitioner
[LinkedIn](#) | [GitHub](#)

## License

MIT
