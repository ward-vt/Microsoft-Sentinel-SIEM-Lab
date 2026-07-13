# Microsoft Sentinel SIEM Home Lab

## Overview

This project demonstrates the deployment and configuration of a cloud-native Security Information and Event Management (SIEM) solution using Microsoft Sentinel on Azure. The lab simulates a real-world SOC (Security Operations Center) environment, covering log ingestion, threat detection, KQL querying, and security dashboarding.

## Tools & Technologies

- Microsoft Azure (Free Tier)
- Microsoft Sentinel
- Log Analytics Workspace
- Microsoft Defender Portal
- Microsoft Entra ID
- Kusto Query Language (KQL)
- Azure Activity Logs
- Microsoft Sentinel Content Hub

## Lab Architecture

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

## Phase 1 — Log Analytics Workspace

Created a Log Analytics Workspace (`sentinel-law-lab`) in the East US region as the foundational data store for all security logs. This workspace serves as the backend for Microsoft Sentinel.

**Configuration:**

| Setting | Value |
|---|---|
| Subscription | Azure Subscription 1 |
| Region | East US |
| Pricing Tier | Pay-as-you-go (Per GB 2018) |

**Screenshots:** `01-log-analytics-workspace-create.png`, `02-log-analytics-deployment-complete.png`, `03-log-analytics-workspace-overview.png`

## Phase 2 — Microsoft Sentinel Deployment

Enabled Microsoft Sentinel on the Log Analytics Workspace. Sentinel provides the SIEM and SOAR capabilities needed for threat detection, investigation, and response.

**Screenshot:** `04-sentinel-enabled.png`

## Phase 3 — Data Connectors (Content Hub)

Installed the following solutions from the Microsoft Sentinel Content Hub to enable log ingestion:

| Solution | Purpose |
|---|---|
| Microsoft Entra ID | Ingests Audit Logs for identity-related activity |
| Azure Activity | Ingests Azure resource management and administrative logs |

> **Note:** SigninLogs ingestion requires a Microsoft Entra ID P1 or P2 license. The free Azure tenant used in this lab does not include this license by default, which prevented Sign-In Log ingestion. This is a known licensing consideration in production environments where P1/P2 licensing must be factored into the SIEM deployment plan.

**Screenshots:** `05-content-hub.png`, `06-entra-id-solution-installed.png`, `07-azure-activity-installed.png`

## Phase 4 — KQL Threat Hunting Queries

Wrote and executed three KQL (Kusto Query Language) queries in the Log Analytics Workspace to demonstrate threat hunting capabilities.

### Query 1 — Failed Sign-ins

Detects authentication failures which may indicate brute force or credential stuffing attacks.

```kql
SigninLogs
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, ResultDescription, IPAddress, Location
| order by TimeGenerated desc
```

**Screenshot:** `08-kql-failed-signins.png`

### Query 2 — New User Created

Detects when new user accounts are created, which could indicate unauthorized account provisioning.

```kql
AuditLogs
| where OperationName == "Add user"
| project TimeGenerated, InitiatedBy, TargetResources
```

**Screenshot:** `09-kql-new-user.png`

### Query 3 — RBAC Role Assignments

Detects changes to role assignments, which could indicate privilege escalation attempts.

```kql
AuditLogs
| where OperationName contains "role assignment"
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

**Screenshot:** `10-kql-rbac-assignments.png`

## Phase 5 — Analytics Rule (Detection Engineering)

Created a scheduled analytics rule to automatically detect brute force attacks by identifying patterns of repeated authentication failures.

**Rule Configuration:**

| Field | Value |
|---|---|
| Rule Name | Brute Force - Multiple Failed Sign-ins |
| Severity | Medium |
| MITRE ATT&CK Tactic | Credential Access |
| MITRE ATT&CK Technique | T1110 - Brute Force |
| Rule Type | Scheduled Query |
| Status | Enabled |

**Detection Query:**

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Rule Logic:** Triggers an incident when a single user account generates 5 or more failed authentication attempts within a 5-minute window.

**Screenshots:** `11-analytics-rules-page.png`, `12-analytics-rule-review.png`, `13-analytics-rule-enabled.png`

## Phase 6 — Incident Detection

The analytics rule was successfully configured and enabled. Simulated brute force attempts were performed to trigger the detection rule.

> **Note:** Due to the Microsoft Entra ID P1/P2 licensing limitation described in Phase 3, SigninLogs were not ingested into the workspace, and no incidents were generated. In a production environment with appropriate licensing, this rule would automatically create incidents in the Incidents queue when the detection threshold is met. The rule logic and configuration are correct and would function as expected with proper data ingestion.

## Phase 7 — Workbooks (Security Dashboard)

Deployed the Azure Activity workbook from the Content Hub to visualize Azure resource activity and operational trends. The workbook provides:

- Top 10 active resource groups
- Activities over time
- Caller activity analysis
- Failure and warning event summaries

**Screenshots:** `14-workbooks-page.png`, `15-workbook-saved.png`, `16-workbook-dashboard.png`

## Key Takeaways

- Deployed a fully functional cloud-native SIEM using Microsoft Sentinel
- Understood the relationship between Log Analytics Workspaces and Sentinel
- Configured data connectors to ingest identity and activity logs
- Wrote KQL queries to detect suspicious activity patterns
- Built a detection rule aligned with MITRE ATT&CK framework (T1110)
- Deployed a security dashboard workbook for operational visibility
- Identified real-world licensing requirements (Entra ID P1/P2) for SigninLogs ingestion — a critical consideration in enterprise SIEM deployments

## Author

**Ta'Lor Ward**
GitHub: [ward-vt](https://github.com/ward-vt)
