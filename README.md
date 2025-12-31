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

# Summary

# Set up

The logs are from a sample of Microsoft Sentinel Training Lab Solution. Once you have install or integrating the data you can go through the log and look for incidents and alerts.

Before creating rules I had to make sure the logs ingested and the data connectors are integrated with Microsoft Defender XDR. Currently Microsoft sentinel and Defender XDR are intergrading and there are some work around to get the log ingested.  Log in to [portal.azure.com](http://portal.azure.com) search for Microsoft Sentinel and choose your workspace. On the navigation bar on the left scroll down until you see Section `Configuration` and choose `Data connectors`. Search for `XDR` to find `Microsoft Defender XDR` and `Open connector page`. In this situation I am only looking for alerts for login attempts so I will be adding `AlertInfo` and `AlertEvidence`. 

Microsoft Defender XDR includes:

- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender for Office 365
- Microsoft Defender for Cloud Apps
- Microsoft Defender Alerts
- Microsoft Purview Data Loss Prevention
- Microsoft Entra ID Protection

With these integration it allow organizations to protect, defend endpoints and respond to sophisticated threats. This allow the different data types/tables.

| **Microsoft Defender for Endpoint** |  |
| --- | --- |
| DeviceInfo | Machine information (including OS information) |
| DeviceNetworkInfo | Network properties of machines |
| DeviceProcessEvents | Process creation and related events |
| DeviceNetworkEvents | Network connection and related events |
| DeviceFileEvents | File creation, modification, and other file system events |
| DeviceRegistryEvents | Creation and modification of registry entries |
| DeviceLogonEvents | Sign-ins and other authentication events |
| DeviceImageLoadEvents | DLL loading events |
| DeviceEvents | Additional events types |
| DeviceFileCertificateInfo | Certificate information of signed files |

| **Microsoft Defender for Office 365** |  |
| --- | --- |
| EmailEvents | Office 365 email events, including email delivery and blocking events |
| EmailUrlInfo | Information about URLs on Office 365 emails |
| EmailAttachmentInfo | Information about files attached to Office 365 emails |
| EmailPostDeliveryEvents | Security events that occur post-delivery, after Office 365 has delivered an email message to the recipient mailbox |
| UrlClickEvents | Events involving URLs clicked, selected, or requested on Microsoft Defender for Office 365 |

| **Microsoft Defender for Cloud Apps** |  |
| --- | --- |
| CloudAppEvents | Events involving accounts and objects in Office 365 and other cloud apps and services |

| **Microsoft Defender for Identity** |  |
| --- | --- |
| IdentityLogonEvents | Authentication activities made through your on-premises Active Directory |
| IdentityQueryEvents | Information about queries performed against Active Directory objects |
| IdentityDirectoryEvents | Captures various identity-related events |

| **Microsoft Defender Alerts** |  |
| --- | --- |
| AlertInfo | Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization. |
| AlertEvidence | Files, IP addresses, URLs, users, or devices associated with alerts. |

On I have install the connectors I head back to https://security.microsoft.com/ which is Microsoft Defender. On the left hand navigation choose `Microsoft Sentinel`, `Configuration` then `Analytics`. On the Analytics page this allow for creating the install connectors to query the log for the specifics failed login. To create new alert click the + Create, Scheduled query rule. Fill out the information on this query and on the Set rule logic you can create the query. Save the query and Review + create and save the rule.

```jsx
SecurityEvent_CL
|where EventID_s == "4625"
|summarize FailedLogons = count() by Account_s
|where FailedLogons >= 1000`
```

Microsoft Defender XDR uses KQL. This query the table SecurityEvent_CL and looks with that table for column EventID_s  which row equals “4625”. EventID 4625: An Account failed to log on is the query I want to search for. Failed attempts is the first indicator of possible brute force attack. Brute force attack is where attacker will use automated software to guess every possible combimation or use leaked information to gain unauthorized access to a system and piviot in the network. Some common attacks are:

- Dictionary Attack
- Credential Stuffing
- Hybrid attack
- Reverse Brute Force attack
- Password Spraying

[(Check resources for more information)](https://www.notion.so/Failed-Login-Attempts-2d90c3b8580a806fbd67ebc0f8a7c93e?pvs=21)

After allowing the rule to run head over to Inestigation & response, under the Incidents & alerts choose Incidents. This is where you will find the alert rule you just created working. Make sure to choose the time frame you are seeking for any alerts to show. Here you can investigate the incident and see the severity for each incident. This allow you to learn more about the invetigation and deep dive into give organization answer they are seeking. 

Let’s dive into some of these incidents. 

# Solorigate Network Beacon

Summary

Malicious code are used to gain foothold in the network which attacker can gain elevated credentials. Attacker compromise organization’s trusted SAML token - signing certificate to impersonate existing users and accounts. 

Resources:

https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

# Sign-ins from IPs that attempt sign-ins to disable

# **Malicious Inbox Rule, affected user**

# Appendix

# Resources

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

https://www.microsoft.com/en-us/download/details.aspx?id=50034

# Notes:

Incident:

Domain: avsvmcloud[.]com - VT - 14/95, Malicious, command and control, Secheduled detection, 7 years, December 2020

IP: 17.81.146.1 - Congguan, China, Domain Name: apple.com, ISP: Apple Inc.

Oct 14, 2025 8:55:45 PM - Seen 5 incident all within 1 second. 

Advance Hunting:

What endpoint is affected?

How did the beacon get downloaded?

Has it been removed?

Has endpoint been isolated from network?

Cisco_Unbrella_dns_CL 

Timeline:

Sep 12, 2019 8:00:00 PM - Cisco_Unbrella_dns_CL  detect interal IP: 17.81.146.1, External IP: 15.230.137.45 ← This external ip is amazon web service in Ashburn, Virginia.

