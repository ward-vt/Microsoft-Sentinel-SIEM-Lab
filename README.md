# Microsoft Sentinel SIEM Home Lab

A cloud-native SIEM built on Azure to practice the core SOC workflow: ingest logs, hunt with KQL, write a detection rule, and visualize activity.

**Stack:** Microsoft Sentinel · Log Analytics · Microsoft Entra ID · Azure Activity · KQL · MITRE ATT&CK

## What this lab demonstrates

| Skill | Evidence in this repo |
| --- | --- |
| SIEM deployment | Log Analytics workspace with Microsoft Sentinel enabled (Phases 1-2) |
| Log ingestion | Entra ID and Azure Activity connectors from the Content Hub (Phase 3) |
| Threat hunting | Three KQL queries: failed sign-ins, new users, RBAC role changes (Phase 4) |
| Detection engineering | Scheduled analytics rule mapped to MITRE ATT&CK T1110 (Phase 5) |
| Dashboards | Azure Activity workbook (Phase 7) |
| Real-world constraints | Documented the Entra ID P1/P2 licensing limit on sign-in logs (Phases 3 and 6) |

## Lab architecture

```
Azure Subscription
└── Resource Group (taloriam-rg)
    └── Log Analytics Workspace (sentinel-law-lab)
        └── Microsoft Sentinel
            ├── Data Connectors
            │   ├── Microsoft Entra ID (Audit Logs)
            │   └── Azure Activity
            ├── Analytics Rules
            │   └── Brute Force - Multiple Failed Sign-ins
            ├── KQL Queries
            │   ├── Failed Sign-ins
            │   ├── New User Created
            │   └── RBAC Role Assignments
            └── Workbooks
                └── Azure Activity Dashboard
```

## Phase 1: Log Analytics workspace

Created the workspace `sentinel-law-lab` in East US as the data store for all security logs and the backend for Sentinel.

| Setting | Value |
| --- | --- |
| Region | East US |
| Pricing tier | Pay-as-you-go (Per GB 2018) |

## Phase 2: Microsoft Sentinel deployment

Enabled Sentinel on the workspace to add SIEM and SOAR capabilities for detection, investigation, and response.

## Phase 3: Data connectors

Installed two Content Hub solutions to start log ingestion.

| Solution | Purpose |
| --- | --- |
| Microsoft Entra ID | Audit logs for identity activity |
| Azure Activity | Azure resource management and administrative logs |

> **Limitation:** Sign-in log ingestion requires a Microsoft Entra ID P1 or P2 license, which the free tenant did not include. In production, that licensing has to be part of the SIEM deployment plan.

## Phase 4: KQL threat hunting queries

**Query 1: Failed sign-ins.** Surfaces authentication failures that may indicate brute force or credential stuffing.

```kql
SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, ResultDescription, IPAddress, Location
| order by TimeGenerated desc
```

**Query 2: New user created.** Flags account creation that could indicate unauthorized provisioning.

```kql
AuditLogs
| where OperationName == "Add user"
| project TimeGenerated, InitiatedBy, TargetResources
```

**Query 3: RBAC role assignments.** Flags role changes that could indicate privilege escalation.

```kql
AuditLogs
| where OperationName contains "role assignment"
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

## Phase 5: Analytics rule (detection engineering)

| Field | Value |
| --- | --- |
| Rule name | Brute Force - Multiple Failed Sign-ins |
| Severity | Medium |
| MITRE ATT&CK | Credential Access, T1110 Brute Force |
| Rule type | Scheduled query |
| Status | Enabled |

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Logic:** raise an incident when one account has 5 or more failed sign-ins within 5 minutes.

## Phase 6: Incident detection (status)

The rule is configured and enabled. Simulated failed sign-ins did not generate an incident because sign-in logs were not ingested (see the Phase 3 limitation). The rule logic is in place, and the next step below is what completes this phase.

## Phase 7: Workbook (security dashboard)

Deployed the Azure Activity workbook to visualize top resource groups, activity over time, caller activity, and failure and warning events.

## Key takeaways

- Built a working cloud SIEM and explained how Log Analytics and Sentinel relate.
- Wrote KQL hunts for failed sign-ins, user creation, and privilege changes.
- Built a detection rule aligned to MITRE ATT&CK T1110.
- Found and documented a real licensing constraint that affects SIEM planning.

## Next steps

- Link the Microsoft Entra ID P2 trial to the main Azure tenant to enable SigninLogs ingestion.
- Generate failed sign-ins on a test account to trigger the rule and capture the resulting incident.
- Document the investigation: alert, evidence, findings, and recommendation.

## Author

**Ta'Lor Ward** · [github.com/ward-vt](https://github.com/ward-vt)
