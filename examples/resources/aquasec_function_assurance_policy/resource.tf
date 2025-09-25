resource "aquasec_function_assurance_policy" "example_function_assurance_policy" {
  //Required values
  application_scopes = ["Global"]
  name               = "example_function_assurance_policy"
  assurance_type     = "function"

  //Values that default to true
  audit_on_failure = true
  block_failed     = true
  fail_cicd        = true

  function_integrity_enabled    = true
  enforce_excessive_permissions = true
  scan_sensitive_data           = true
  cvss_severity                 = "critical"
  cvss_severity_enabled         = true

}