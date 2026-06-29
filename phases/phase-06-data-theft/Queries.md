# Phase 06 - Data Theft: Queries

> Query log for Phase 06. These queries separate file access from file download, count the stolen files, identify the credential document, and confirm the vault pointer.

---

## Q22 - The Exfil Operation

**Purpose:** Determine which action type represents actual exfiltration.

**KQL Query**
```kql
CloudAppEvents
| where ActionType in ("FileDownloaded", "FileAccessed")
| project Timestamp,
          ActionType,
          ObjectName,
          AccountDisplayName,
          Application
| order by Timestamp asc
```

**Expected Result:** `FileDownloaded`, not `FileAccessed`.

**Pivot Produced:** Exfiltration action, `FileDownloaded`.

**Investigation Value:** Prevents counting normal access/viewing as data theft.

---

## Q23 - Volume Taken

**Purpose:** Count the downloaded files and list them.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| project Timestamp,
          ActionType,
          ObjectName,
          AccountDisplayName,
          Application
| order by Timestamp asc
```

**Expected Result:** `3`, targeted theft of specific high-value files.

**Pivot Produced:** Download count, `3`.

**Investigation Value:** Shows targeted collection rather than bulk scraping.

---

## Q24 - The Credential Document

**Purpose:** Identify downloaded credential material.

**KQL Query**
```kql
CloudAppEvents
| where ObjectName has "VPN-Access-Credentials"
| project Timestamp,
          ActionType,
          ObjectName,
          AccountDisplayName,
          Application
| order by Timestamp asc
```

**Expected Result:** `VPN-Access-Credentials.txt`

**Pivot Produced:** Credential file, `VPN-Access-Credentials.txt`.

**Investigation Value:** Identifies the second vector, VPN credential access beyond the original mailbox.

---

## Q25 - The Vault Pointer

**Purpose:** Identify the PDF that pointed toward additional credential storage.

**KQL Query**
```kql
CloudAppEvents
| where ObjectName has ".pdf"
| project Timestamp,
          ActionType,
          ObjectName,
          AccountDisplayName,
          Application
| order by Timestamp asc
```

**Expected Result:** `yomark.pdf`, observed as an access event.

**Pivot Produced:** Vault pointer, `yomark.pdf`.

**Investigation Value:** Preserves the important distinction: `yomark.pdf` was accessed, while the exfiltration count remains three downloaded files.

---

## Supporting Query - High-Value File Names

**Purpose:** Search for credential, VPN, vault, banking, or vendor related file names.

**KQL Query**
```kql
CloudAppEvents
| where ObjectName has_any ("credential", "credentials", "vpn", "vault", "bank", "vendor", "payment")
| project Timestamp,
          ActionType,
          ObjectName,
          AccountDisplayName,
          Application
| order by Timestamp asc
```

**Expected Result:** Returns high-value file activity relevant to credential expansion and fraud.

**Pivot Produced:** Sensitive-file activity timeline.

**Investigation Value:** Supports hunting for related theft beyond the exact challenge answer.