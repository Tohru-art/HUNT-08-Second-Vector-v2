# Phase 06 - Data Theft

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Quantify what was taken. Identify the exfiltration action, the volume of files removed, and the specific high-value documents stolen, particularly anything that expands the attacker's access beyond the original compromised identity. This phase establishes the "second vector" the investigation is named for: the credential material that turns one compromised account into a path to more.

## Scope

- File-access/download telemetry attributable to the compromised session
- Identification of stolen documents by name and sensitivity
- No automation/trigger analysis, that is Phase 07

## Data Sources

| Source | Role in this phase |
|---|---|
| `CloudAppEvents` | `FileDownloaded` actions, file names, and actor attribution |
| `OfficeActivity` | SharePoint/OneDrive download corroboration where present |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q22: The Exfil Operation | Action type **`FileDownloaded`** | `CloudAppEvents` records of file downloads from the compromised session | The exfiltration method was direct download of cloud-stored files, the attacker pulled documents out rather than forwarding them, leaving a clean download trail to follow. |
| Q23: Volume Taken | **3** files downloaded | Count of `FileDownloaded` events attributable to the session | A small, deliberate set, not bulk scraping. The low volume signals targeted theft of specific high-value documents, consistent with the recon in Phase 03. |
| Q24: The Credential Document | **`VPN-Access-Credentials.txt`** | File name on one of the download events | This is the second vector. VPN credentials provide network-level access independent of the compromised mailbox/identity, a path that survives even if `m.smith` is contained. |
| Q25: The Vault Pointer | **`yomark.pdf`** | File name on one of the download events | A document that points toward a credential vault / additional stored secrets, the attacker collecting the map to *more* credentials, extending reach further. |

## Key Pivot Values

```
Exfil action     : FileDownloaded
Volume           : 3 files
Credential file  : VPN-Access-Credentials.txt   (network access, the "second vector")
Vault pointer    : yomark.pdf                    (path to additional secrets)
Objective        : credential expansion + second-vector access
```

## Analyst Assessment

This phase names the investigation. The "second vector" is `VPN-Access-Credentials.txt`.

The attacker downloaded exactly three files, a targeted pull, not a smash-and-grab, and the selection tells you the goal. VPN credentials give network-level access that does not depend on the original Azure AD identity, so even a perfect cleanup of `m.smith` would not necessarily evict the attacker if those credentials remain valid. `yomark.pdf` compounds the problem: it points toward a credential vault, meaning the attacker was not just taking credentials but collecting directions to more of them. Together these turn a single-identity email compromise into a credential-expansion operation with at least one access path outside the mailbox.

The low file count is itself a finding. It reflects the deliberate, recon-informed targeting seen in Phase 03, the attacker knew what they wanted before they took it.

## Detection Opportunities

- **Sensitive-filename download alerting**, alert on downloads of files matching credential/secret patterns (`*credential*`, `*vpn*`, `*password*`, `*vault*`) from any session, with elevated severity from a risk-flagged source.
- **Download burst from anonymized IP**, flag multiple `FileDownloaded` events from a session whose source IP is tagged `anonymizedIPAddress` or is a known IOC (`103.69.224.136`).
- **Post-recon download correlation**, chain a directory-recon burst (Phase 03) to a subsequent targeted download set from the same session as a high-confidence "collection" signal.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Data from Cloud Storage | T1530 | Direct download of files from cloud storage via the compromised session |
| Unsecured Credentials: Credentials In Files | T1552.001 | Theft of `VPN-Access-Credentials.txt`, credentials stored in a plaintext file |
| Data from Information Repositories | T1213 | Collection of `yomark.pdf` pointing to additional stored secrets |

## Response Considerations

- **Rotate and revoke the stolen VPN credentials immediately**, this is the access path that survives mailbox containment. Treat the VPN account as compromised.
- Hunt for VPN authentications using the stolen credentials, especially from `103.69.224.136`, `185.130.187.4`, or anonymized sources, and review VPN logs for the incident window forward.
- Identify and secure whatever `yomark.pdf` points to; rotate any secrets reachable through that pointer.
- Add both file names to the case IOC set and confirm whether either was also forwarded externally via the Phase 05 rule.
