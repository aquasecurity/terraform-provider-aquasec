## 0.15.1 (June 24, 2026)

BUG FIXES:

* `aquasec_application_scope_saas`: Fix "unexpected end of JSON input" error on all CRUD operations. The SaaS code path was routing to an incorrect API endpoint. Now uses the auto-resolved CSP URL with the correct `/api/v2/access_management/scopes` path. No user configuration change required. ([#388](https://github.com/aquasecurity/terraform-provider-aquasec/pull/388))

## 0.1.0 (Unreleased)

BACKWARDS INCOMPATIBILITIES / NOTES:
