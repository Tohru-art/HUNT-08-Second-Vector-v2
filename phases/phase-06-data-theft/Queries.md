# Phase 06 - Data Theft: Queries

> Query log for Phase 06. Focus is the exfiltration: the download action, the volume, and the specific high-value files, especially the credential material that forms the second vector.

---

## Q22 - The Exfil Operation

**Purpose:** Identify the action type the attacker used to exfiltrate data.

**KQL Query**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType == "FileDownloaded"
| where IPAddress in ("103.69.224.136", "185.130.187.4")
      or AccountObjectId == "<m.smith objectId>"
| project TimeGenerated, ActionType, AccountDisplayName, IPAddress,
          ObjectName, RawEventData
| order by TimeGenerated asc
```

**Expected Result:** `FileDownloaded` events attributable to the compromised session.

**Pivot Produced:** Exfil action, `FileDownloaded`.

**Investigation Value:** Confirms the exfiltration method as direct cloud download, giving a precise event type to count and enumerate.

---

## Q23 - Volume Taken

**Purpose:** Count how many files were downloaded during the compromise.

**KQL Query**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType == "FileDownloaded"
| where IPAddress in ("103.69.224.136", "185.130.187.4")
| summarize FilesDownloaded = dcount(ObjectName),
            Files = make_set(ObjectName)
```

**Expected Result:** **3** distinct files downloaded.

**Pivot Produced:** Volume, 3 files (targeted, not bulk).

**Investigation Value:** Quantifies the theft and characterizes it as deliberate, recon-informed targeting.

---

## Q24 - The Credential Document

**Purpose:** Identify the credential file among the downloaded set.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| where ObjectName has_any ("credential", "vpn", "password")
| project TimeGenerated, AccountDisplayName, IPAddress, ObjectName
| order by TimeGenerated asc
```

**Expected Result:** **`VPN-Access-Credentials.txt`**.

**Pivot Produced:** Second-vector credential file, `VPN-Access-Credentials.txt`.

**Investigation Value:** Identifies the network-access path that survives mailbox containment, the namesake of the investigation.

---

## Q25 - The Vault Pointer

**Purpose:** Identify the document that points toward additional stored secrets.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| where IPAddress in ("103.69.224.136", "185.130.187.4")
| project TimeGenerated, AccountDisplayName, ObjectName
| order by TimeGenerated asc
```

**Expected Result:** **`yomark.pdf`** appears in the downloaded set as the vault pointer.

**Pivot Produced:** Vault pointer, `yomark.pdf`.

**Investigation Value:** Reveals the attacker was collecting directions to further credentials, extending the credential-expansion objective.
