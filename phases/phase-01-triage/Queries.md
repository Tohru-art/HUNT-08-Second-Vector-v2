# Phase 01 - Triage: Queries

> Query log for Phase 01. These queries move from tenant-wide identity risk to the confirmed compromised user, attacker source, client OS, risk type, risk verdict, and account state.

---

## Q01 - The Compromised Principal

**Purpose:** Identify which user generated the suspicious Identity Protection risk cluster.

**KQL Query**
```kql
AADUserRiskEvents
| summarize Detections = count() by UserPrincipalName
| order by Detections desc
```

**Expected Result:** `m.smith@lognpacific.org`

**Pivot Produced:** Compromised UPN, `m.smith@lognpacific.org`.

**Investigation Value:** Establishes the primary user pivot for the rest of the hunt.

---

## Q02 - The Flagged Source

**Purpose:** Identify the suspicious source IP tied to the compromised principal.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize SignIns = count() by IPAddress
| order by SignIns desc
```

**Expected Result:** `103.69.224.136`

**Pivot Produced:** Attacker IP, `103.69.224.136`.

**Investigation Value:** Provides the master infrastructure pivot reused throughout the case.

---

## Q03 - The Client OS

**Purpose:** Determine the operating system reported by the suspicious sign-ins.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| extend ClientOS = tostring(DeviceDetail.operatingSystem)
| summarize SignIns = count() by ClientOS
| order by SignIns desc
```

**Expected Result:** `Linux`

**Pivot Produced:** Client OS, `Linux`.

**Investigation Value:** Adds device-context evidence that the sign-in did not match expected corporate user behavior.

---

## Q04 - The Stored Detection Type

**Purpose:** Identify the risk detection type stored by Entra ID Protection.

**KQL Query**
```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize Detections = count() by RiskEventType
| order by Detections desc
```

**Expected Result:** `anonymizedIPAddress`

**Pivot Produced:** Risk type, `anonymizedIPAddress`.

**Investigation Value:** Confirms Microsoft recognized anonymized infrastructure as part of the sign-in activity.

---

## Q05 - Audit to Verdict

**Purpose:** Determine how the generated risk detections were resolved.

**KQL Query**
```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize Events = count() by RiskState
| order by Events desc
```

**Expected Result:** `dismissed`

**Pivot Produced:** Risk verdict, `dismissed`.

**Investigation Value:** Shows the issue was not lack of visibility. The detection existed, but response failed.

---

## Q06 - Live Exposure

**Purpose:** Confirm whether the compromised account was still enabled.

**KQL Query**
```kql
IdentityInfo
| where AccountUPN == "m.smith@lognpacific.org"
| project Timestamp, AccountUPN, AccountEnabled
| order by Timestamp desc
| take 1
```

**Expected Result:** `AccountEnabled == true`, meaning the account was `Enabled`.

**Pivot Produced:** Account state, `Enabled`.

**Investigation Value:** Confirms the compromised identity remained live and usable.