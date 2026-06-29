# HUNT-08: Second Vector

A DFIR investigation into token persistence, business email compromise, Microsoft Graph abuse, mailbox-rule persistence, and Power Automate driven mail exfiltration.

> Analyst: Will-Garlens Pierre, SOC Analyst
> Environment: Log(N) Pacific Cyber Range
> Platforms: Microsoft Sentinel, Microsoft Defender XDR, Microsoft Entra ID
> Investigation Type: Cloud DFIR / Threat Hunting / Incident Response
> Primary Query Language: KQL

---

# Executive Summary

An external actor compromised the cloud identity `m.smith@lognpacific.org` and operated inside the tenant from an anonymized source IP address, `103.69.224.136`.

Microsoft Entra ID Protection successfully detected the malicious authentication activity and generated risk detections associated with anonymized infrastructure. The detections were subsequently dismissed, leaving the compromised identity active and available for continued abuse.

The attacker did not bypass MFA.

Instead, they leveraged an existing Keep Me Signed In (KMSI) refresh token, allowing access through `singleFactorAuthentication` without requiring a new MFA challenge. Conditional Access policies were never evaluated against these sessions because `ConditionalAccessStatus` remained `notApplied` throughout the compromise window.

With persistent access established, the actor performed Microsoft Graph reconnaissance to profile MFA posture and enumerate groups, hijacked an existing banking change conversation, deployed mailbox rules to conceal verification messages, forwarded mail externally to ProtonMail infrastructure, and exfiltrated cloud-stored files.

The investigation ultimately revealed that the fraudulent mail activity was not performed by an interactive user session.

The forwarding operation was executed by a malicious Microsoft Power Automate flow operating through Microsoft Graph API requests.

This discovery fundamentally changed containment priorities.

The correct response sequence became:

1. Revoke active sessions.
2. Remove the malicious flow.
3. Reset credentials.

Resetting credentials first would have left both the refresh token and automation workflow operational.

---

# Attack Narrative

| Stage                       | Description                                                              | Phase    |
| --------------------------- | ------------------------------------------------------------------------ | -------- |
| Initial Access              | Compromise of `m.smith@lognpacific.org` from anonymized infrastructure   | Phase 01 |
| Session Persistence         | KMSI refresh token reuse through `singleFactorAuthentication`            | Phase 02 |
| Discovery                   | MFA posture profiling and group enumeration through Microsoft Graph      | Phase 03 |
| Fraud Operations            | Banking detail modification attempt using existing business conversation | Phase 04 |
| Mail Persistence            | Mailbox concealment and external forwarding rules                        | Phase 05 |
| Collection and Exfiltration | Download of credential-related files and vault references                | Phase 06 |
| Automation Execution        | Power Automate workflow executes Graph mail actions                      | Phase 07 |
| Correlation and Containment | Cross-source attribution and response sequencing                         | Phase 08 |

---

# Repository Structure

```text
HUNT-08-Second-Vector/
│
├── README.md
│
└── phases/
    │
    ├── phase-01-triage/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-02-session-scope/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-03-directory-recon/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-04-fraud/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-05-persistence-hunt/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-06-data-theft/
    │   ├── Findings.md
    │   └── Queries.md
    │
    ├── phase-07-plant-and-trigger/
    │   ├── Findings.md
    │   └── Queries.md
    │
    └── phase-08-correlation-containment/
        ├── Findings.md
        └── Queries.md
```

Each phase contains:

* Investigation findings
* Supporting evidence
* Relevant telemetry sources
* Analyst interpretation
* MITRE ATT&CK mappings
* Response recommendations
* KQL used during the investigation

---

# Indicators of Compromise

| Type           | Indicator                                      | Context                                |
| -------------- | ---------------------------------------------- | -------------------------------------- |
| Attacker IP    | `103.69.224.136`                               | Primary infrastructure pivot           |
| Secondary IP   | `185.130.187.4`                                | Secondary mail activity                |
| Automation IP  | `20.150.129.194`                               | Microsoft Graph mail automation source |
| External Email | `merovingian1337@proton.me`                    | Mail forwarding destination            |
| App ID         | `7ab7862c-4c57-491e-8a45-d52a7e023983`         | Power Automate application identity    |
| File           | `VPN-Access-Credentials.txt`                   | Credential theft target                |
| File           | `yomark.pdf`                                   | Vault pointer                          |
| Mail Rule      | `Invoice Processing`                           | Mail concealment rule                  |
| Subject        | `Updated Banking Details - Pacific IT Monthly` | Fraud conversation                     |

Compromised identity:

* `m.smith@lognpacific.org`

Targeted finance contact:

* `j.reynolds@lognpacific.org`

---

# MITRE ATT&CK Mapping

| Tactic            | Technique                                                 | ID        |
| ----------------- | --------------------------------------------------------- | --------- |
| Initial Access    | Valid Accounts: Cloud Accounts                            | T1078.004 |
| Defense Evasion   | Use Alternate Authentication Material: Web Session Cookie | T1550.004 |
| Discovery         | Account Discovery: Cloud Account                          | T1087.004 |
| Discovery         | Permission Groups Discovery                               | T1069.003 |
| Collection        | Email Collection                                          | T1114     |
| Collection        | Email Forwarding Rule                                     | T1114.003 |
| Defense Evasion   | Hide Artifacts: Email Hiding Rules                        | T1564.008 |
| Persistence       | Account Manipulation                                      | T1098     |
| Collection        | Data from Cloud Storage                                   | T1530     |
| Credential Access | Credentials In Files                                      | T1552.001 |
| Collection        | Data from Information Repositories                        | T1213     |
| Execution         | Serverless Execution                                      | T1648     |

---

# Containment Strategy

1. Revoke active sessions associated with the compromised identity.
2. Remove the malicious Power Automate flow.
3. Reset credentials for the compromised account.
4. Remove malicious mailbox rules.
5. Rotate VPN credentials and associated secrets.
6. Implement Conditional Access enforcement.
7. Block malicious indicators and perform retrospective hunting.
8. Review dismissed risk detections and incident triage decisions.

## Why revoke before reset?

Password resets do not invalidate active refresh tokens.

An attacker maintaining access through KMSI persistence can continue operating even after a password change unless active sessions are revoked first.

Similarly, delegated Power Automate workflows continue executing independently of interactive sign-ins until explicitly removed.

---

# Investigation Outcome

| Area           | Result                                    |
| -------------- | ----------------------------------------- |
| Initial Access | Compromised cloud credentials             |
| Persistence    | Refresh token reuse                       |
| Discovery      | Graph reconnaissance                      |
| Collection     | Mail monitoring                           |
| Exfiltration   | External forwarding and file theft        |
| Automation     | Power Automate workflow abuse             |
| Impact         | Business email compromise                 |
| Containment    | Session revocation and automation removal |

---

# Key Lessons Learned

* Detection without response is ineffective.
* Password resets do not invalidate refresh tokens.
* Conditional Access coverage gaps become attack paths.
* Power Automate can become a persistence mechanism.
* Microsoft Graph telemetry is critical during cloud investigations.
* Response sequencing matters as much as response actions.

---

# Skills Demonstrated

* Digital Forensics and Incident Response
* Threat Hunting
* Microsoft Sentinel
* Microsoft Defender XDR
* Microsoft Entra ID
* Microsoft Graph Analysis
* Power Automate Abuse Analysis
* Business Email Compromise Investigation
* Mailbox Rule Analysis
* KQL Development
* MITRE ATT&CK Mapping
* Incident Containment and Recovery

---

# Technologies Used

* Microsoft Sentinel
* Microsoft Defender XDR
* Microsoft Entra ID
* Microsoft Graph
* Microsoft Power Automate
* Kusto Query Language (KQL)

---

Investigation conducted within the Log(N) Pacific cyber range environment.

All findings are evidence-based and reproducible using the documented KQL queries included throughout the repository.
