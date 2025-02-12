// Basic Policy with CIS Benchmarks
data "aquasec_host_assurance_policy" "cis_example" {
  name = "cis-policy"
}

output "cis_checks" {
  value = {
    linux    = data.aquasec_host_assurance_policy.cis_example.linux_cis_enabled
    windows  = data.aquasec_host_assurance_policy.cis_example.windows_cis_enabled
    docker   = data.aquasec_host_assurance_policy.cis_example.docker_cis_enabled
    kubernetes = data.aquasec_host_assurance_policy.cis_example.kube_cis_enabled
  }
}



// Vulnerability Management Example
data "aquasec_host_assurance_policy" "vuln_example" {
  name = "vulnerability-policy"
}

output "vulnerability_settings" {
  value = {
    max_score = data.aquasec_host_assurance_policy.vuln_example.maximum_score
    enabled   = data.aquasec_host_assurance_policy.vuln_example.maximum_score_enabled
    exclude_no_fix = data.aquasec_host_assurance_policy.vuln_example.maximum_score_exclude_no_fix
  }
}

// Auto Scan Configuration Example
data "aquasec_host_assurance_policy" "autoscan_example" {
  name = "autoscan-policy"
}

output "scan_schedule" {
  value = data.aquasec_host_assurance_policy.autoscan_example.auto_scan_time
}


