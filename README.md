# 🔐 Incident Report: Azure Brute-Force Detection & Investigation

![Status](https://img.shields.io/badge/status-closed-brightgreen) ![Severity](https://img.shields.io/badge/risk-low-brightgreen) ![Platform](https://img.shields.io/badge/platform-Microsoft%20Sentinel-0078D4) ![Framework](https://img.shields.io/badge/framework-NIST%20SP%20800--61-blue)

| | |
|---|---|
| **Report ID** | `IR-2026-0827-BF01` |
| **Incident Status** | Closed — False Positive (Benign, Confirmed) |
| **Overall Risk Rating (Post-Investigation)** | Low |
| **Frameworks Referenced** | NIST SP 800-61 Rev. 2 · MITRE ATT&CK v15 |
| **Platform / Tooling** | Microsoft Sentinel · Microsoft Defender for Endpoint · KQL |

---

## 📝 Executive Summary

This report documents the detection, investigation, and closure of a Microsoft Sentinel incident triggered by a repeated authentication failure (brute-force) detection rule across six Azure-hosted virtual machines. This report includes triaging the resulting incident, performing root-cause analysis on a successful authentication event, and closing the incident in accordance with the NIST SP 800-61 Incident Response Lifecycle.

Six distinct source IP addresses generated 10 or more failed logon attempts within a 10-hour window against six separate virtual machines. Of the six sources, five were external, internet-facing addresses whose failed-logon activity never resulted in a successful authentication; these remain unauthorized access attempts and were remediated through network-layer controls. The sixth source, an internal address (`10.0.0.8`), was confirmed through log correlation, process-execution analysis, and device-identity lookup to be an authenticated vulnerability scan engine (`LOCAL-SCAN-ENGINE-01`) performing routine, credentialed Nessus scanning — not malicious activity. No evidence of compromise, lateral movement, data access, or persistence was identified on any in-scope asset.

> **This incident is closed with a final disposition of False Positive / Benign — Confirmed, with residual risk items tracked separately as control-improvement actions.**

---

## ⚠️ Risk Summary

The table below summarizes each notable finding from the investigation and its associated risk disposition.

| Finding | Likelihood | Impact | Inherent Risk | Disposition |
|---|---|---|---|---|
| 5 external IPs — sustained failed-logon attempts, no successful authentication | Low (post-remediation) | Medium | 🟠&nbsp;Medium&nbsp;→&nbsp;🟢&nbsp;Low | NSG rules tightened; IPs blocked at network edge |
| `10.0.0.8` — successful authentication flagged by brute-force rule | N/A | N/A | 🟢&nbsp;False&nbsp;Positive | Confirmed benign (Nessus scan engine); rule tuned |
| `LOCAL-SCAN-ENGINE-01` not onboarded to Defender for Endpoint | Medium | Medium | 🟠&nbsp;Medium | Open — onboarding recommended |
| Device ownership for `LOCAL-SCAN-ENGINE-01` recorded as "Unknown" | Medium | Low | 🟠&nbsp;Low-Medium | Open — ownership assignment recommended |

---

## 🎯 MITRE ATT&CK Mapping

| Category | ID | Name | Relevance |
|---|---|---|---|
| Tactic | [TA0006](https://attack.mitre.org/tactics/TA0006/) | Credential Access | Objective of the observed activity across all six source IPs |
| Technique | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Repeated failed authentication attempts detected by the analytics rule |
| Sub-technique (candidate) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) / [.003](https://attack.mitre.org/techniques/T1110/003/) | Password Guessing / Password Spraying | Applicable to the 5 external sources pending further pattern analysis (single vs. multiple target accounts) |
| Technique (ruled out) | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remote Services: Windows Remote Management | Initially considered during deep-dive on `10.0.0.8`; confirmed to be legitimate WMI-based scan execution, not adversary use |

---

## 🛠 Part 1 — Detection Engineering: Brute-Force Alert Rule

Designed a Microsoft Sentinel Scheduled Query Rule that identifies when the same remote IP address fails to authenticate to the same Azure-hosted VM 10 or more times within a 10-hour window.

### Detection Logic (KQL)

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated >= ago(10h)
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName, AccountName
| where NumberOfFailures >= 10
| order by NumberOfFailures desc
```

### Analytics Rule Configuration

- Rule enabled and scheduled to run every 4 hours
- Lookback period: last 10 hours (defined in query)
- MITRE ATT&CK categories mapped to the rule (Credential Access / Brute Force — see [MITRE ATT&CK Mapping](#-mitre-attck-mapping))
- Entity mappings configured for Remote IP and Device Name to support automated entity-based investigation
- Alert grouping: all triggering alerts consolidated into a single incident per 24-hour period
- Query throttling: rule suppressed from re-triggering 24 hours after an alert is generated, to reduce duplicate incidents
- Incident auto-creation enabled on rule trigger

---

## 🔎 Part 2 — Incident Response: Detection and Analysis

The incident was completed in accordance with the NIST SP 800-61 Rev. 2 Incident Response Lifecycle.

### Detection and Analysis

**Identification and Validation**
- Observed the incident in Microsoft Sentinel, assigned to myself, and set status to Active
- Investigated using **Actions → Investigate with Microsoft Defender**

  <img width="839" height="572" alt="bf-grapf-1" src="https://github.com/user-attachments/assets/c454e48d-cbb7-4ab5-a567-a18df925f8dc" />

**Evidence Gathering — Affected Assets**

Entity mappings on the triggering incident identified six distinct source IP addresses generating failed-logon activity against six distinct hosts within the lookback window:

| Source IP | Failed Attempts | Target Host | Origin | Successful Logon? |
|---|---|---|---|---|
| `45.153.34.149` | 41 | Linux-target-1 | External | ❌ No |
| `10.0.0.8` | 13 | winserv-e-826 | Internal | ⚠️ Yes* |
| `185.118.79.103` | 88 | Tareq-test-vm | External | ❌ No |
| `186.10.4.106` | 40 | winserv-e-826 | External | ❌ No |
| `91.92.47.66` | 90 | Linux-scan-agent | External | ❌ No |
| `88.214.25.125` | 18 | Mrdn-bkp01 | External | ❌ No |

<sub>*Successful authentication from `10.0.0.8` was subsequently confirmed as benign — see [Part 3](#-part-3--root-cause-analysis-internal-source-10008).</sub>

**Successful-Logon Validation Query**

The following query was used to confirm whether any brute-force source achieved successful authentication against its targeted host:

```kql
DeviceLogonEvents
| where RemoteIP in ("45.153.34.149", "185.118.79.103", "186.10.4.106",
                     "91.92.47.66", "88.214.25.125", "10.0.0.8")
| where ActionType == "LogonSuccess"
| where TimeGenerated >= ago(10h)
| summarize NumberOfSuccess = count() by RemoteIP, ActionType, DeviceName, AccountName
```
<img width="883" height="291" alt="Success-login" src="https://github.com/user-attachments/assets/01c21a6e-ec2c-408d-85af-73770e57fd88" />

**Result:** five of the six source IP addresses (all externally originating) recorded zero successful logons and are assessed as unsuccessful, unauthorized brute-force attempts. One source, `10.0.0.8` (an internal address), recorded multiple successful authentications and was escalated for deep-dive analysis, documented in Part 3.

---

## 🕵️ Part 3 — Root Cause Analysis: Internal Source (10.0.0.8)

Because `10.0.0.8` is an internal, non-routable address, a successful authentication from this source carried different risk implications than an external source and was treated as a potential lateral-movement indicator until proven otherwise. The following evidence chain was built to determine root cause.

### Containment (Precautionary)

Standard containment actions were identified for execution had this incident been assessed as an active compromise:

- Isolate affected devices via Microsoft Defender for Endpoint (all 6 in-scope devices)
- Run anti-malware scans across all 6 in-scope devices within MDE
- Restrict the Network Security Group (NSG) attached to each affected VM to permit only expected management traffic

### Evidence Chain

**1. Process Execution Context**

Command-line and process telemetry was reviewed for the successful-logon window to determine what activity, if any, occurred under the authenticated session:

```kql
DeviceProcessEvents
| where DeviceName == "my-servervm-woo"
| where TimeGenerated between (datetime(2026-08-27T11:40:30) .. datetime(2026-08-27T11:41:00))
| where InitiatingProcessAccountName == "woody" or AccountName == "woody"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1352" height="541" alt="Process Execution Context" src="https://github.com/user-attachments/assets/b9840872-bff7-43bd-bd2c-99e497557ae4" />

**Findings:** command lines were explicitly prefixed with the string `nessus_cmd_` and executed via `wmiprvse.exe` (Windows Management Instrumentation [WMI]-based remote execution) — the expected execution pattern for an authenticated Nessus vulnerability scan. Observed activity included queries to the Azure Instance Metadata Service (`168.63.129.16`) and standard host-enumeration commands (`netstat -ano`, `tasklist /FO csv /svc`), consistent with credentialed vulnerability-scan reconnaissance rather than adversary tooling.

**2. Device Identity Confirmation**

To rule out credential theft or IP spoofing, the device owning `10.0.0.8` was positively identified via network configuration telemetry:

```kql
// Confirms private IP-to-device assignment
DeviceNetworkInfo
| where TimeGenerated >= ago(1d)
| mv-expand IPAddresses
| where tostring(IPAddresses.IPAddress) == "10.0.0.8"
| distinct DeviceName, DeviceId
```
<img width="998" height="117" alt="Device Identity Confirmation" src="https://github.com/user-attachments/assets/9f8949ff-5c3c-41ca-8b2d-8c0585f23246" />

**Result:** `10.0.0.8` resolved to device `LOCAL-SCAN-ENGINE-01` (Azure resource group `Cyber-Range-Admin`), a Windows 10 host. Asset attributes were reviewed in Microsoft Defender's device inventory to corroborate the finding — see the Device Attribute Summary below.
<img width="959" height="314" alt="Screenshot 2026-08-27 162016" src="https://github.com/user-attachments/assets/21a1e54f-d751-4ece-9dde-6e14f057a895" />

**3. Human Confirmation**

Findings were validated with organizational stakeholders responsible for vulnerability management, who confirmed `10.0.0.8` / `LOCAL-SCAN-ENGINE-01` as the organization's designated Nessus scan engine and that the observed scan window aligned with an expected, scheduled scan job.

### Device Attribute Summary — LOCAL-SCAN-ENGINE-01

| Attribute | Value |
|---|---|
| **Device Name** | `LOCAL-SCAN-ENGINE-01` |
| **Device ID** | `fb7cd64ed76fb1fe25561e87877a3b9d19aa1b6b` |
| **Private IP** | `10.0.0.8` |
| **Operating System** | Windows 10, 22H2 (Build 19045) |
| **Azure Resource Group** | `Cyber-Range-Admin` |
| **Criticality** | Medium |
| **Device Classification** | Transient |
| **MDE Onboarding Status** | Not onboarded — "Can be onboarded" |
| **Managed By** | Unknown at time of investigation |
| **First / Last Seen (Discovery)** | Aug 10, 2024 – Aug 27, 2026 (passive discovery only) |

### Root Cause Determination

**Root cause:** the brute-force analytics rule correctly detected a real pattern of repeated authentication activity from `10.0.0.8`, but the activity's source was a legitimate, credentialed vulnerability scanner cycling through multiple scan-account credentials in rapid succession — not an adversary. The rule performed as designed; the disposition is a true-positive detection of benign activity (a tuning opportunity), not a detection failure.

### Detection Rule Tuning

An exclusion was added to the brute-force detection rule to prevent recurring false-positive incidents from the confirmed scan engine, using a Sentinel Watchlist for maintainability:

```kql
let ExcludedIPs = (_GetWatchlist('TrustedScanners') | project SearchKey);
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated >= ago(10h)
| where RemoteIP !in (ExcludedIPs)
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName, AccountName
| where NumberOfFailures >= 10
| order by NumberOfFailures desc
```

The watchlist-based approach was selected over a hardcoded IP exclusion so that vulnerability-management stakeholders can maintain the list of trusted sources without requiring changes to the detection rule logic itself.

---

## ✅ Post-Incident Activities and Recommendations

### Actions Taken

- Network Security Groups (NSGs) on affected VMs updated to restrict inbound traffic to only expected/authorized sources, closing off direct internet exposure of management ports
- Brute-force detection rule tuned to exclude the confirmed vulnerability scan engine via watchlist
- Incident reviewed, resolution confirmed, and closed in Microsoft Sentinel with a disposition of "False Positive"

### Control Gaps Identified (Residual Risk)

The following items are independent of this incident's direct cause but were surfaced during the investigation and are recommended for tracking as separate remediation actions:

- **Onboard `LOCAL-SCAN-ENGINE-01` to Microsoft Defender for Endpoint.** The device currently operates with credentialed, scheduled access across the fleet but is only passively discovered, not actively monitored — limiting visibility into its own behavior and creating an attractive, lower-visibility foothold if ever compromised.
- **Assign and document formal ownership for `LOCAL-SCAN-ENGINE-01`.** Ownership is currently recorded as "Unknown," which is a gap for asset accountability and incident escalation purposes.
- **Formalize a corporate policy requiring restrictive NSG baselines** (default-deny inbound) for all newly provisioned VMs, rather than remediating exposure after detection.
- **Extend the trusted-scanner watchlist approach** to other recurring, credentialed internal automation (backup agents, monitoring tools) to reduce future alert fatigue without weakening detection coverage for genuine threats.

---

## 🏁 Closure

| | |
|---|---|
| **Final Disposition** | False Positive — Benign, Confirmed (internal source); Unsuccessful Attack — Remediated (external sources) |
| **Incident Status** | Closed |
| **Framework Alignment** | NIST SP 800-61 Rev. 2 |
| **Outstanding Items** | MDE onboarding and ownership assignment for `LOCAL-SCAN-ENGINE-01` (tracked separately) |

