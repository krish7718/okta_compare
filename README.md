# OktaVerse

`OktaVerse` is a unified toolkit for Okta environment analysis, documentation, comparison, and migration.

This repository currently includes multiple utilities under the `OktaVerse` umbrella:

- `OktaCompare`: Compare configuration between two Okta environments and generate a report + CSV export.
- `OktaSnapshot`: Capture and export a structured snapshot of a single Okta org's configuration.
- `OktaEvaluate`: Tenant security assessment utility with validation checks and exportable reports.
- `OktaMigrate`: Migration utility for comparing entities and migrating selected missing entities (current demo scope: Groups).

## OktaVerse Structure

- `OktaCompare` (`/`): Main comparison workflow with report generation and CSV exports.
- `OktaSnapshot` (`/snapshot`): Snapshot guide generation with PDF and DOCX export support.
- `OktaEvaluate` (`/evaluate`, `/validate`): Security assessment workflow with CSV/PDF export support.
- `OktaMigrate` (`/migrate`): Compare-and-migrate workflow (demo scope currently enabled for Groups).

## OktaCompare

Compare configuration between two Okta environments and generate a report + CSV export.

## Docker

You can run `OktaVerse` locally in Docker.

### Prerequisites
- Docker installed and running

### 1. Build the image
```bash
docker build -t oktaverse .
```

### 2. Run the container
```bash
docker run --rm -p 5000:5000 --name oktaverse oktaverse
```

### 3. Open the app
- `http://localhost:5000` (`OktaCompare`)
- `http://localhost:5000/snapshot` (`OktaSnapshot`)
- `http://localhost:5000/evaluate` (`OktaEvaluate`)
- `http://localhost:5000/migrate` (`OktaMigrate`)

### Useful Docker commands

Run in detached mode:
```bash
docker run -d --rm -p 5000:5000 --name oktaverse oktaverse
```

View logs:
```bash
docker logs -f oktaverse
```

Stop the container:
```bash
docker stop oktaverse
```

Use a different host port (example: `8080`):
```bash
docker run --rm -p 8080:5000 --name oktaverse oktaverse
```
Then open `http://localhost:8080`.

Notes:
- The app runs on port `5000` inside the container.
- PDF export (`OktaSnapshot`) is intended to work in Docker because the image installs the required system libraries for `WeasyPrint`.

## Run Locally

You can also run `OktaVerse` directly on your local machine with Python.

### Prerequisites
- Python `3.10+`
- `pip`

### 1. Create and activate a virtual environment

macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install Python libraries

```bash
pip install -r requirements.txt
```

The project currently depends on:
- `flask`
- `pandas`
- `python-docx`
- `requests`
- `weasyprint`

Note:
- `WeasyPrint` may require additional OS-level libraries on some machines for PDF generation. If PDF export fails but the app starts, the Python install is usually fine and the missing dependency is at the system-library level.

### 3. Start the app

```bash
python app.py
```

The Flask app starts on:
- `http://localhost:5000`

### 4. Open the tools

- `http://localhost:5000` for `OktaCompare`
- `http://localhost:5000/snapshot` for `OktaSnapshot`
- `http://localhost:5000/evaluate` for `OktaEvaluate`
- `http://localhost:5000/migrate` for `OktaMigrate`

### 5. Stop the app

Press `Ctrl+C` in the terminal running the Flask server.

## OktaCompare Legend
- Critical: high-risk mismatch or missing object in an environment.
- Medium: configuration mismatch for a matched object.
- Low: extra object found in one environment.
- Match: values are identical.

## OktaCompare Entities and Compared Parameters

| Entity | Key / Matching Strategy | Compared Parameters / Notes |
|---|---|---|
| Groups | Group profile name | Description |
| Group Rules | Rule name (group IDs in expressions normalized to group names) | Condition expression |
| Network Zones | Zone name | Type, gateways, proxies, locations, status |
| Applications | App label/name + internal app type (`name` or `signOnMode`) | Existence; explicit comparison of directory-style apps such as `active_directory` and `csv_directory`; profile source status via `/api/v1/apps/{id}/features` when `PROFILE_MASTERING` is `ENABLED`; group assignments only if `compare_group_assignments=True` |
| Authenticators | Authenticator key/name | Name, type, status |
| Authenticator Enrollment Policies | Policy name | Policy existence and per-rule comparison for rule name, status, priority, conditions, and actions |
| Global Session Policies | Policy name | Policy-level comparison of status, priority, description, and conditions; per-rule comparison of priority, status, conditions, and actions |
| Password Policies | Policy name | Policy and per-rule comparison including status, priority, description, conditions, settings, and rule actions |
| App Sign-On Policies | Policy name | Policy-level comparison of status, priority, description, and conditions; per-rule comparison of priority, status, conditions, and actions |
| IDP Discovery Policies | Policy name | Policy existence and rule-by-rule comparison of rule status, priority, conditions, and actions |
| Profile Enrollment Policies | Policy name | Policy and per-rule comparison including status, priority, description, conditions, settings, and rule actions |
| Entity Risk Policies | Policy name | Policy and per-rule comparison including status, priority, description, conditions, settings, and rule actions |
| Identity Threat Protection Policies | Policy name | Policy and per-rule comparison including status, priority, description, conditions, settings, and rule actions |
| Brand Settings | Brand name | Brand properties (`name`, `removePoweredByOkta`, privacy policy fields, `isDefault`) and theme properties (logo/colors/page variants/assets) |
| Brand Pages | Brand name | Sign-in page `pageContent` HTML; error page settings signature (IDs/links excluded); widget customization diffs logged |
| Brand Email Templates | Brand name + template name | Customization subject and body/`htmlBody` |
| Authorization Servers - Settings | Authorization server name | Server settings, claims list, scopes list (IDs/links/timestamps excluded) |
| Authorization Servers - Access Policies | Authorization server name + policy name | Rule signature (name, status, priority, conditions, actions) |
| Custom Admin Roles | Role label/name | Role settings signature (IDs/links/timestamps excluded) |
| Resource Sets | Resource set label/name | Resource set settings signature (IDs/links/timestamps excluded) |
| Admin Assignments | Set comparison (users/groups/apps) | Admin users (`login/email/displayName/userId`), admin groups (`name/groupId`), admin apps (`displayName/appInstanceId`) |
| API Tokens | Token name | Full API token metadata from list/detail endpoints including status, client/user metadata, expiry, last updated, and network settings |
| Security General Settings | Sanitized settings object | Threats config, ThreatInsight, security notifications, captcha, user enumeration, user lockout, authenticator settings (IDs/links/timestamps excluded) |
| Org General Settings | `/api/v1/org` (sanitized) | All fields except `id`, `_links`, `created`, `lastUpdated`, `expiresAt`, `subdomain` |
| Identity Providers | IdP name | Status, `protocol.type`, sanitized policy |
| Realms | Realm name/label/displayName | Realm settings signature (IDs/links/timestamps excluded) |
| Realm Assignments | Assignment name/label/displayName | Status, conditions, actions, domains, `isDefault`, priority |
| Profile Schema - User | Attribute name | Full user profile attribute settings (base + custom schemas) |
| Profile Mappings | `source.name -> target.name` (IdP app user mappings only) | Property mappings (`targetField`, source expression, `pushStatus`) |
| Trusted Origins | Origin name (or URL) | Settings signature (IDs/links/timestamps excluded) |
| Event Hooks | Event hook name | Full event hook settings signature including status, channel/config, auth scheme, and subscribed events (IDs/links/timestamps excluded) |
| Inline Hooks | Inline hook name | Full inline hook settings signature including type, status, channel/config, auth scheme, and version (IDs/links/timestamps excluded) |
| Access Controls - Attack Protection | Object/component name | Authenticator settings, user lockout settings, bot protection config, org-wide CAPTCHA settings, behavior detection rules, and CAPTCHA instance metadata |
| Group Push Mappings | App + source/target group mapping | Full group push mapping settings per app using list/detail mapping endpoints |

Notes:
- Compare currently covers all supported entities listed above.
- Snapshot currently extracts all supported entities listed below.

## OktaSnapshot Extracted Entities

| OktaSnapshot Section | Type | Notes |
|---|---|---|
| Organization Settings | Extracted | Key-value settings from org configuration |
| Security General Settings | Extracted | Security settings rows |
| Groups | Extracted | Group inventory for snapshot guide/export |
| Group Rules | Extracted | Rule inventory/details |
| Network Zones | Extracted | Zone definitions |
| Identity Providers | Extracted | IdP configurations |
| Authenticators | Extracted | Authenticator inventory/settings |
| Authorization Servers - Settings | Extracted | Authorization server settings entries |
| Authorization Server Claims | Extracted | Claims inventory |
| Authorization Server Scopes | Extracted | Scopes inventory |
| Authorization Servers - Access Policies | Extracted | Policies and rules combined in one section (`Entry Type`) |
| Applications | Extracted | Application inventory/details |
| Password Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Global Session Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Authentication Policies | Extracted | Policies and rules combined (`Entry Type`) |
| MFA Enrollment Policies | Extracted | Policies and rules combined (`Entry Type`) |
| IDP Discovery Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Profile Enrollment Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Entity Risk Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Identity Threat Protection Policies | Extracted | Policies and rules combined (`Entry Type`) |
| Brand Settings | Extracted | Brand/theme settings rows |
| Brand Pages | Extracted | Brand page content/settings rows |
| Brand Email Templates | Extracted | Template customization rows |
| Custom Admin Roles | Extracted | Role definitions |
| Resource Sets | Extracted | Resource sets, resources, and bindings combined (`Entry Type`) |
| Admin Assignments - Users | Extracted | Admin user assignments |
| Admin Assignments - Groups | Extracted | Admin group assignments |
| Admin Assignments - Apps | Extracted | Admin app assignments |
| API Tokens | Extracted | Token inventory/settings |
| Realms | Extracted | Realm definitions |
| Realm Assignments | Extracted | Realm assignment rows |
| Profile Schema - User | Extracted | User schema attributes |
| Profile Mappings | Extracted | Mapping rows (filtered snapshot view) |
| Trusted Origins | Extracted | Trusted origin rows |
| Event Hooks | Extracted | Event hook inventory/settings |
| Inline Hooks | Extracted | Inline hook inventory/settings |
| Access Controls - Attack Protection | Extracted | Authenticator settings, user lockout, behaviors, bot protection, CAPTCHA instances, and org CAPTCHA settings |
| Group Push Mappings | Extracted | Group push mappings with app context and mapping settings |

## OktaEvaluate

Perform tenant security assessment checks and generate an exportable validation report.

### Key Capabilities

- Runs tenant-level security validation checks using live Okta configuration data.
- Produces a structured report with: `What Was Checked`, `Result`, `Severity`, and `Details`.
- Flags high/moderate security gaps across notifications, policies, session settings, factors, and apps.
- Exports the assessment report as CSV (PDF route is also available in the app).

### Current Coverage

| Check Area | Example Checks | Severity |
|---|---|---|
| App Sign-On / Authentication Policies | Catch-all/default deny posture | High |
| Session Security | Session lifetime exceeds recommended 2 hours | High |
| Security Notifications | Password changed, suspicious activity, sign-on, factor enrollment/reset notifications | High |
| MFA / Factor Enrollment | Weaker factors configured; optional factors in factor enrollment policies | High / Moderate |
| Password Policies | Weak password policy heuristics (complexity/lockout/common passwords) | Moderate |
| Network Zones | Presence of blocklisted zone | Moderate |
| Applications | SAML-supported apps that are disabled | High |

## OktaMigrate

Compare source and target Okta configuration entities, identify missing entities, and migrate selected entities into the target environment.

### Key Capabilities

- Compares source and target environments for migration-oriented entity gaps.
- Presents missing entities for selection and targeted migration into the target tenant.
- Includes migration execution guidance sections: `Execution Phases`, `Risk Register (Initial)`, `Assumptions & Inputs`.
- Supports selective entity migration actions (current demo scope: `Groups`).

### Current Demo Scope (Groups)

| Capability | Behavior |
|---|---|
| Entity Scope | `Groups` selectable; other entities shown but disabled for demo |
| Comparison | Lists all source groups and identifies missing groups in target |
| Selection | Checkbox per missing group |
| Migration Action | `Migrate` button creates selected missing groups in target via Okta API |
| Group Type Filter | Only `OKTA_GROUP` groups are listed and created |

## OktaCompare Export Behavior
- Triggered by the “Export Comparison Report” button on the report page.
- Exports a CSV with columns: Category, Object, Attribute, Env A Value, Env B Value, Difference Type, Impact, Recommended Action, Priority.
- Priority values are text only (Critical/Medium/Low/Match); icons are not included.
- Export is generated in-memory from the latest comparison run and is not persisted.
