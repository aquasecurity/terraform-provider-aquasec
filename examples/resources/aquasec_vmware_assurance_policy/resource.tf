resource "aquasec_vmware_assurance_policy" "example_vmware_assurance_policy" {
  // Required values
  application_scopes = ["Global"]
  name               = "example_vmware_assurance_policy"

  // Values default to true
  audit_on_failure = true
  block_failed     = true
  fail_cicd        = true

  scan_sensitive_data   = true
  cvss_severity_enabled = true
  cvss_severity         = "critical"
}