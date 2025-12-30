# Failed-Login-Attempts

## Objective

To investigate repeated failed login attempts using Microsoft Sentinel Training Lab logs and Microsoft Defender XDR. This project demonstrates my ability to integrate data connectors, analyze authentication events, create alert rules, and identify potential brute‑force activity using KQL. The goal was to understand how failed logons appear across different Microsoft security tools and how to triage them using a SOC‑style workflow

### Skills Learned

- Integrating Microsoft Defender XDR data connectors (AlertInfo, AlertEvidence) into Microsoft Sentinel
- Understanding how Defender for Endpoint, Identity, Office 365, and Cloud Apps generate security telemetry
- Reviewing authentication‑related tables such as DeviceLogonEvents, IdentityLogonEvents, and SecurityEvent_CL
- Writing KQL queries to detect failed logon attempts (Event ID 4625)
- Identifying patterns consistent with brute‑force techniques (dictionary attacks, credential stuffing, password spraying, etc.)
- Creating scheduled analytics rules in Sentinel to alert on excessive failed logons
- Investigating alerts in Microsoft Defender XDR and reviewing severity, evidence, and related entities
- Understanding how failed logons can lead to larger incidents (e.g., Solorigate‑style lateral movement or credential misuse)
- Strengthening SOC triage workflow: verify → analyze → correlate → conclude
- Documenting findings clearly and referencing threat intelligence source


### Tools Used

- Microsoft Defender XDR – alert investigation, evidence review, identity and endpoint telemetry
- Microsoft Sentinel – KQL queries, analytics rules, data connectors, incident triage
- Azure Portal – workspace configuration, connector setup, subscription management
- Log Analytics Workspace – central log ingestion and query engine
- Windows Event Viewer – understanding Event ID 4625 and authentication behavior
- CyberChef – decoding and data parsing
- VirusTotal – validating suspicious domains and IP addresses
- Notepad++ – note‑taking and log review
- Cisco Umbrella Logs – DNS‑based threat visibility (Cisco_Unbrella_dns_CL)


## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
