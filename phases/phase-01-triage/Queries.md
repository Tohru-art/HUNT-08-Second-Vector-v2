# Phase 01 - Triage: Queries

> Query log for Phase 01. Each entry records why the query was run, the KQL executed, the expected result, the pivot it produced, and its investigation value. Queries reconstructed from the confirmed findings reflect the path an analyst takes from a single risk detection to a confirmed foothold.

---

## Q01 - The Compromised Principal

**Purpose:** Identify which identity in the tenant is generating Identity Protection risk detections so the rest of the hunt has a single pivot point.

**KQL Query**
```kql
AADUserRiskEvents
| summarize Detections = count() by UserPrincipalName, RiskEventType
| order by Detections desc
```

**Expected Result:** `m.smith@lognpacific.org` surfaces as the principal carrying the cluster of risk detections.

**Pivot Produced:** Compromised UPN, `m.smith@lognpacific.org`.

**Investigation Value:** Converts a tenant-wide risk signal into a named identity. Every subsequent query in the investigation filters on this UPN.

---

## Q02 - The Flagged Source

**Purpose:** Determine the source IP address that Identity Protection associated with the risky activity for the compromised principal.

**KQL Query**
```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize Detections = count() by IpAddress
| order by Detections desc
```

**Expected Result:** `103.69.224.136` is the dominant source IP behind the risk detections.

**Pivot Produced:** Attacker IP, `103.69.224.136`.

**Investigation Value:** This IP becomes the master correlation value reused in Phases 04 and 08 to prove a single actor touched multiple telemetry tables.

---

## Q03 - The Client OS

**Purpose:** Identify the operating system used during the malicious sign-ins to test whether the device profile matches the user's normal behavior.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| extend ClientOS = tostring(DeviceDetail.operatingSystem)
| summarize count() by ClientOS
| order by count_ desc
```

**Expected Result:** Sign-ins from the flagged IP report `Linux` as the client OS.

**Pivot Produced:** Client OS, Linux (out-of-profile for a corporate Windows user).

**Investigation Value:** Establishes a behavioral anomaly that strengthens the compromise hypothesis beyond the IP signal alone.

---

## Q04 - The Stored Detection Type

**Purpose:** Identify the specific risk detection type Identity Protection recorded, to understand what the platform actually saw.

**KQL Query**
```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by RiskEventType
| order by count_ desc
```

**Expected Result:** `anonymizedIPAddress` is the recorded detection type.

**Pivot Produced:** Risk type, `anonymizedIPAddress`.

**Investigation Value:** Confirms the attacker reached the tenant from behind an anonymizing service, which both explains the IP geolocation and raises the bar on why the detection should not have been dismissed.

---

## Q05 - Audit to Verdict

**Purpose:** Determine how the generated risk detections were resolved, were they acted on or closed out?

**KQL Query**
```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by RiskState
| order by count_ desc
```

**Expected Result:** The majority of detections carry `RiskState == dismissed`.

**Pivot Produced:** Verdict, dismissed.

**Investigation Value:** Reframes the incident from "tooling missed it" to "tooling caught it and triage overrode it." This is the root-cause thread for the after-action review.

---

## Q06 - Live Exposure

**Purpose:** Confirm whether the compromised account was still enabled and usable at the time of investigation.

**KQL Query**
```kql
IdentityInfo
| where AccountUPN == "m.smith@lognpacific.org"
| project AccountUPN, AccountEnabled, AccountObjectId, Timestamp
| order by Timestamp desc
| take 1
```

**Expected Result:** `AccountEnabled == true`.

**Pivot Produced:** Account state, Enabled (live exposure).

**Investigation Value:** Confirms the foothold is active, not historical, and sets the urgency for the containment ordering decision finalized in Phase 08.
