//Example: Basic host assurance policy with essential settings
resource "aquasec_host_assurance_policy" "basic" {
  name               = "host_policy_basic"
  description        = "Basic host assurance policy for production hosts"
  application_scopes = ["Global"]

  # Basic policy settings
  enabled           = true
  audit_on_failure  = true
  block_failed      = true

  # CIS Benchmarks
  docker_cis_enabled    = true
  kube_cis_enabled      = true
  linux_cis_enabled     = true
  windows_cis_enabled   = false

  # Vulnerability scanning settings
  cvss_severity_enabled       = true
  cvss_severity              = "high"
  cvss_severity_exclude_no_fix = false
  maximum_score_enabled       = true
  maximum_score              = 8
  vulnerability_score_range   = [8, 10]

  # Malware scanning
  disallow_malware = true
  malware_action   = "alert"
  monitored_malware_paths = [
    "/tmp",
    "/var/tmp"
  ]

  # Auto scanning configuration
  auto_scan_enabled      = true
  auto_scan_configured   = true
  auto_scan_time {
    iteration_type = "daily"
    time           = "2024-01-01T12:00:00Z"
  }
}

// Example: Advanced host assurance policy with key settings
resource "aquasec_host_assurance_policy" "advanced" {
  
  name               = "host_policy_advanced"
  description        = "Advanced host assurance policy with key security controls"
  application_scopes = ["Global"]

  # Policy enforcement
  enabled           = false
  audit_on_failure  = true
  block_failed      = true


  # Vulnerability management
  cvss_severity_enabled         = true
  cvss_severity                = "critical"
  maximum_score_enabled         = true
  maximum_score                = 7
  vulnerability_score_range     = [7, 10]

  # CIS compliance checks
  docker_cis_enabled    = true
  kube_cis_enabled      = true
  linux_cis_enabled     = true

  # Malware scanning configuration
  disallow_malware = true
  malware_action   = "block"
  monitored_malware_paths = [
    "/tmp",
    "/var/tmp"
  ]

  # Auto scanning configuration
  auto_scan_enabled      = true
  auto_scan_configured   = true
  auto_scan_time {
    iteration_type = "daily"
    time           = "2024-01-01T00:00:00Z"
  }

  # Basic policy settings
  policy_settings {
    enforce          = true
    warn             = true
    warning_message  = "Host failed security compliance checks"
  }
}