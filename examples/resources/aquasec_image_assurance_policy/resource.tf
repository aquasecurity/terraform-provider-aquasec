resource "aquasec_image_assurance_policy" "test_image_policy" {
  // Required values
  name               = "test_image_assurance_policy"
  application_scopes = ["Global"]

  // Below options default to true:
  block_failed     = true
  fail_cicd        = true
  audit_on_failure = true

  // Simple policy looking for critical vulnerabilites,
  // malware, and sensitive data
  cvss_severity         = "critical"
  cvss_severity_enabled = true
  disallow_malware      = true
  scan_sensitive_data   = true

}