# OktaCompare

Compare configuration between two Okta environments and generate a report + CSV export.

## Legend
- Critical: high-risk mismatch or missing object in an environment.
- Medium: configuration mismatch for a matched object.
- Low: extra object found in one environment.
- Match: values are identical.

## Entities and Compared Parameters

### Groups
- Keyed by group profile name.
- Compares: description.

### Group Rules
- Keyed by rule name (group IDs in expressions are replaced with group names).
- Compares: condition expression.

### Network Zones
- Keyed by zone name.
- Compares: type, gateways, proxies, locations, status.

### Applications
- Keyed by app label/name.
- Compares: existence; group assignments only if `compare_group_assignments=True`.

### Authenticators
- Keyed by authenticator key/name.
- Compares: name, type, status.

### Authenticator Enrollment Policies
- Keyed by policy name.
- Compares: rule signature (name, status, priority, conditions, actions). Marked mismatch if any rule differs.

### Password Policies
- Keyed by policy name.
- Compares: rule signature (name, status, priority, conditions, actions). Marked mismatch if any rule differs.

### App Sign-On Policies
- Keyed by policy name.
- Compares: rule signature (name, status, priority, conditions, actions). Marked mismatch if any rule differs.

### IDP Discovery Policies
- Keyed by policy name.
- Compares: rule-by-rule (status, conditions, actions) for matching rule names.

### Profile Enrollment Policies
- Keyed by policy name.
- Compares: rule signature (name, status, priority, conditions, actions). Marked mismatch if any rule differs.

### Brand Settings
- Keyed by brand name.
- Brand properties: name, removePoweredByOkta, customPrivacyPolicyUrl, agreeToCustomPrivacyPolicy, isDefault.
- Theme properties: backgroundImage, emailTemplateTouchPointVariant, endUserDashboardTouchPointVariant, errorPageTouchPointVariant, favicon, loadingPageTouchPointVariant, logo, primaryColorContrastHex, primaryColorHex, secondaryColorContrastHex, secondaryColorHex, signInPageTouchPointVariant.

### Brand Pages
- Keyed by brand name.
- Sign-in page: pageContent HTML.
- Error page: full settings signature (excluding IDs/links).
- Note: widget customizations are logged if they differ.

### Brand Email Templates
- Keyed by brand name and template name.
- Compares: subject and body/htmlBody of customizations.

### Authorization Servers - Settings
- Keyed by authorization server name.
- Compares: server settings, claims list, scopes list (IDs/links/timestamps excluded).

### Authorization Servers - Access Policies
- Keyed by authorization server name and policy name.
- Compares: rule signature (name, status, priority, conditions, actions).

### Custom Admin Roles
- Keyed by role label/name.
- Compares: role settings signature (IDs/links/timestamps excluded).

### Resource Sets
- Keyed by resource set label/name.
- Compares: resource set settings signature (IDs/links/timestamps excluded).

### Admin Assignments
- Compares three sets:
  - Admin users (login/email/displayName/userId).
  - Admin groups (name/groupId).
  - Admin apps (displayName/appInstanceId).

### API Tokens
- Keyed by token name.
- Compares: network settings.

### Security General Settings
- Compares settings for:
  - Threats Configuration
  - ThreatInsight Settings
  - Security Notifications
  - Captcha
  - User Enumeration
  - User Lockout
  - Authenticator Settings
- Comparison uses sanitized settings (IDs/links/timestamps excluded).

### Org General Settings
- Compares all org settings fields from `/api/v1/org` except: id, _links, created, lastUpdated, expiresAt, subdomain.

### Identity Providers
- Keyed by IdP name.
- Compares: status, protocol.type, policy (sanitized).

### Realms
- Keyed by realm name/label/displayName.
- Compares: realm settings signature (IDs/links/timestamps excluded).

### Realm Assignments
- Keyed by assignment name/label/displayName.
- Compares: status, conditions, actions, domains, isDefault, priority.

### Profile Schema - User
- Keyed by attribute name.
- Compares: full attribute settings for the "user" profile (base + custom schemas).

### Profile Mappings
- Scope: only mappings where source or target is an IdP app user type.
- Keyed by `source.name -> target.name`.
- Compares: property mappings (targetField, sourceExpression/expression, pushStatus).

### Trusted Origins
- Keyed by origin name (or origin URL).
- Compares: settings signature (IDs/links/timestamps excluded).

## Export Behavior
- Triggered by the “Export Comparison Report” button on the report page.
- Exports a CSV with columns: Category, Object, Attribute, Env A Value, Env B Value, Difference Type, Impact, Recommended Action, Priority.
- Priority values are text only (Critical/Medium/Low/Match); icons are not included.
- Export is generated in-memory from the latest comparison run and is not persisted.
