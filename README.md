# HUNT-08: Second Vector

**A DFIR investigation into a token-persistence account takeover, business email compromise, and Power Automate-driven mail exfiltration.**

> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Microsoft Defender XDR
> **Discipline:** Identity compromise · BEC · Persistence · Cloud exfiltration · Automation abuse · Containment
> **Primary query language:** KQL

---

## Executive Summary

An external actor compromised the cloud identity `m.smith@lognpacific.org` and operated inside the tenant from an anonymized IP (`103.69.224.136`). Microsoft Entra ID Protection **detected** the malicious sign-ins, and the detections were **dismissed**, leaving the account enabled and the door open.

The attacker did not defeat MFA. They reused a persistent "Keep Me Signed In" refresh token, so subsequent access required only single-factor authentication, and **Conditional Access was never applied** to evaluate the sessions. From that foothold the actor performed directory reconnaissance, ran a **business email compromise** by hijacking a trusted "Updated Banking Details" payment thread, planted **mailbox rules** on the finance contact (`j.reynolds@lognpacific.org`) to conceal verification mail and forward correspondence to an external Proton address, and **exfiltrated three files**, including `VPN-Access-Credentials.txt`, the *second vector* that gives network access independent of the mailbox.

The standout finding: the malicious mail forwarding was **not a human action**. There were **zero** successful MFA logins at the time, and the activity was driven by a planted **Microsoft Power Automate** flow executing through the Microsoft Graph API. The Graph call provably precedes the mail event, cause before effect. Containment therefore hinges on **ordering**: revoke sessions first (live tokens survive a password reset), remove the flow in the Power Platform Admin Center, then reset credentials and rotate the stolen VPN secret.

---

## Attack Narrative (Kill Chain)

| Stage | What happened | Phase |
|---|---|---|
| **Initial Access** | Sign-in as `m.smith` from anonymized IP `103.69.224.136` on a Linux client; ID Protection risk detection **dismissed**, account left **enabled** | 01 |
| **Defense Evasion / Persistence (auth)** | Persistent KMSI refresh token → `singleFactorAuthentication`; Conditional Access `notApplied` | 02 |
| **Discovery** | MFA-status profiling + group enumeration via Microsoft Graph for target selection | 03 |
| **Impact (Fraud)** | BEC: hijacked "Updated Banking Details" payment thread; reinforced across forward/reply | 04 |
| **Persistence (mail)** | "Invoice Processing" rule conceals verification mail; external forward to `merovingian1337@proton.me`; both on `j.reynolds` | 05 |
| **Collection / Exfiltration** | 3 files downloaded, incl. `VPN-Access-Credentials.txt` (second vector) and `yomark.pdf` (vault pointer) | 06 |
| **Execution (Automation)** | Planted **Power Automate** flow drives the forward via Graph; 0 successful MFA; Graph call precedes mail event | 07 |
| **Correlation / Containment** | One actor across 7 telemetry tables; automation `20.150.129.194` / App ID `7ab7862c-…`; revoke-before-reset containment | 08 |

---

## Repository Structure

```
HUNT-08-Second-Vector/
├── README.md                              <- you are here (full investigation overview)
├── Phase-01-Triage/
│   ├── Findings.md
│   ├── Queries.md
│   └── screenshots/
├── Phase-02-Session-Scope/
├── Phase-03-Directory-Recon/
├── Phase-04-The-Fraud/
├── Phase-05-Persistence-Hunt/
├── Phase-06-Data-Theft/
├── Phase-07-The-Plant-and-the-Trigger/
└── Phase-08-Correlation-and-Containment/
        ├── Findings.md
        ├── Queries.md
        └── screenshots/
```

Each phase folder contains a **Findings.md** (objective, scope, data sources, findings table, pivots, analyst assessment, detection opportunities, MITRE mapping, response considerations) and a **Queries.md** (purpose-driven KQL with expected results, pivots produced, and investigation value).

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| IP (attacker) | `103.69.224.136` | Anonymized source; master pivot; appears across 7 telemetry tables |
| IP (attacker) | `185.130.187.4` | Secondary attacker mail-sending infrastructure |
| IP (automation) | `20.150.129.194` | Source of the Power Automate / Graph mail-action requests |
| IP (platform) | `20.190.190.224` | Microsoft service range (NDR / infrastructure), *not* attacker-originated |
| Email (exfil) | `merovingian1337@proton.me` | External forwarding destination |
| App ID | `7ab7862c-4c57-491e-8a45-d52a7e023983` | Power Automate automation identity |
| File | `VPN-Access-Credentials.txt` | Stolen credential file, the "second vector" |
| File | `yomark.pdf` | Vault pointer to additional secrets |
| Mail rule | `Invoice Processing` | Concealment rule on `j.reynolds` mailbox |
| Subject | `Updated Banking Details - Pacific IT Monthly` | BEC fraud message |

**Compromised / targeted identities:** `m.smith@lognpacific.org` (compromised), `j.reynolds@lognpacific.org` (persistence + fraud target).

---

## MITRE ATT&CK Summary

| Tactic | Technique | ID | Phase |
|---|---|---|---|
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | 01, 02, 07, 08 |
| Command & Control | Proxy: Multi-hop Proxy | T1090.003 | 01 |
| Defense Evasion | Use Alternate Authentication Material: Web Session Cookie | T1550.004 | 02, 08 |
| Credential Access | Modify Authentication Process (control gap) | T1556 | 02 |
| Discovery | Account Discovery: Cloud Account | T1087.004 | 03 |
| Discovery | Permission Groups Discovery: Cloud Groups | T1069.003 | 03 |
| Initial Access | Internal Spearphishing | T1534 | 04 |
| Defense Evasion | Impersonation | T1656 | 04 |
| Collection | Email Collection | T1114 | 04 |
| Collection | Email Collection: Email Forwarding Rule | T1114.003 | 05, 07 |
| Defense Evasion | Hide Artifacts: Email Hiding Rules | T1564.008 | 05 |
| Persistence | Account Manipulation | T1098 | 05 |
| Collection | Data from Cloud Storage | T1530 | 06 |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | 06 |
| Collection | Data from Information Repositories | T1213 | 06 |
| Execution | Serverless Execution | T1648 | 07, 08 |

---

## Containment Runbook (Order Matters)

1. **Revoke sessions** for the compromised identity, invalidate live refresh tokens *first*.
2. **Remove the malicious flow** in the **Power Platform Admin Center** (App ID `7ab7862c-…`).
3. **Reset the password**, only *after* sessions are revoked.
4. **Delete the inbox rules** on `j.reynolds` ("Invoice Processing" + external forward).
5. **Rotate the stolen VPN credentials** and secure whatever `yomark.pdf` points to.
6. **Apply Conditional Access**, require MFA, block anonymized sources, enforce sign-in frequency for this user class.
7. **Block IOCs** and retro-hunt the automation IP / App ID tenant-wide.
8. **Re-open and audit** the originally dismissed risk detections; review the triage decision.

**Why this order:** the foothold is a live refresh token plus a flow running on delegated authority. A password reset alone leaves both intact. *Revoke before reset.*

---

## Investigation Outcome

| Stage | Outcome |
|---|---|
| **Initial Access** | Compromised credentials for `m.smith@lognpacific.org`. |
| **Defense Evasion** | Trusted session persistence through KMSI refresh tokens; Conditional Access not applied. |
| **Discovery** | Directory reconnaissance and MFA-registration profiling. |
| **Collection** | Mailbox monitoring and credential harvesting. |
| **Exfiltration** | External forwarding rule plus Power Automate workflow. |
| **Persistence** | Malicious mailbox rules combined with a Microsoft Power Automate flow. |
| **Impact** | Business email compromise involving payment-redirection attempts. |
| **Containment** | Session revocation, flow removal, password reset, Conditional Access validation. |

## Key Lessons

- **Detection without response is not protection.** ID Protection caught this on day one; a dismissal made the whole intrusion possible.
- **KMSI sessions bypass password-reset assumptions.** A reset alone does not invalidate a live refresh token; sessions must be revoked first.
- **Power Automate can act as persistence.** A planted flow keeps executing on delegated authority after the obvious account actions are taken.
- **Microsoft Graph logs are critical for cloud investigations.** The forward looked like a user action; only Graph activity proved it was automation.
- **Conditional Access coverage gaps become identity attack paths.** An unevaluated sign-in is an unprotected one.

---

## Tooling & Skills Demonstrated

`Microsoft Sentinel` · `Microsoft Defender XDR` · `KQL` · `Microsoft Entra ID Protection` · `Microsoft Graph activity analysis` · `Power Platform / Power Automate abuse analysis` · `BEC investigation` · `mailbox-rule persistence hunting` · `cross-source correlation` · `MITRE ATT&CK mapping` · `incident containment & response sequencing`

---

*Investigation conducted in the Log(N) Pacific cyber-range environment as a structured, phased threat hunt. All findings are evidence-based and reproducible from the queries documented in each phase.*
