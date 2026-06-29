# Phase 06 - Data Theft: Queries

> Query log for Phase 06. Focus is the exfiltration: the download action, the volume, and the specific high-value files, especially the credential material that forms the second vector.

---

## Q22 - The Exfil Operation

**Purpose:** Identify the action type the attacker used to exfiltrate data.

**KQL Query**
```kql
CloudAppEvents
| where ActionType in ("FileDownloaded", "FileAccessed")
| project Timestamp, ActionType, ObjectName
| order by Timestamp asc
```

**Expected Result:** The true exfiltration operation is **`FileDownloaded`**, not `FileAccessed`.

**Pivot Produced:** Exfil action, `FileDownloaded`.

**Investigation Value:** Confirms the exfiltration method as direct cloud download and prevents over-counting normal file views.

---

## Q23 - Volume Taken

**Purpose:** Count how many files were downloaded during the compromise.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| project Timestamp, ObjectName
| order by Timestamp asc
```

**Expected Result:** **3** downloaded files, targeted theft of specific high-value files.

**Pivot Produced:** Volume, `3` downloaded files.

**Investigation Value:** Quantifies the theft and characterizes it as deliberate, recon-informed targeting.

---

## Q24 - The Credential Document

**Purpose:** Identify the credential file among the downloaded set.

**KQL Query**
```kql
CloudAppEvents
| where ObjectName has "VPN-Access-Credentials"
```

**Expected Result:** **`VPN-Access-Credentials.txt`**.

**Pivot Produced:** Second-vector credential file, `VPN-Access-Credentials.txt`.

**Investigation Value:** Identifies the network-access path that survives mailbox containment, the namesake of the investigation.

---

## Q25 - The Vault Pointer

**Purpose:** Identify the PDF that points toward additional stored secrets.

**KQL Query**
```kql
CloudAppEvents
| where ObjectName has ".pdf"
| project Timestamp, ActionType, ObjectName
| order by Timestamp asc
```

**Expected Result:** **`yomark.pdf`** appears as a PDF access event. It should not be counted as one of the three downloaded files unless `ActionType` explicitly shows `FileDownloaded`.

**Pivot Produced:** Vault pointer, `yomark.pdf`.

**Investigation Value:** Reveals the attacker was collecting directions to further credentials, while preserving the correct distinction between accessed and downloaded evidence.