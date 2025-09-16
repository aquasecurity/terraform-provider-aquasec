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

resource "aquasec_image_assurance_policy" "img1" {
  allowed_images {
      imagename   = "hello-world"
      registry    = "docker.io"
      author      = "terraform-user"
      blacklisted = false
      whitelisted = true
      imagedigest = ""
      imageid     = 0
      lastupdated = 0
      reason      = [
          "Approved image"
      ]
  }
  application_scopes                   = [
      "Global",
  ]
  audit_on_failure                     = true
  auto_scan_configured                 = false
  auto_scan_enabled                    = false
  blacklist_permissions                = [
      "delete"
  ]
  blacklist_permissions_enabled        = true
  blacklisted_licenses                 = [
      "LGPL","GPL",
  ]
  blacklisted_licenses_enabled         = true
  block_failed                         = true
  control_exclude_no_fix               = true
  custom_checks_enabled                = false
  custom_severity_enabled              = true
  cves_black_list                      = [
      "CVE-2022-6754",
  ]
  cves_black_list_enabled              = true
  cves_white_list                      = [
      "CVE-2022-6755",
  ]
  cves_white_list_enabled              = true
  cvss_severity                        = "low"
  cvss_severity_enabled                = true
  cvss_severity_exclude_no_fix         = true
  description                          = "Testing IMG Policy"
  disallow_malware                     = true
  docker_cis_enabled                   = true
  dta_enabled                          = true
  enabled                              = true
  enforce                              = true
  enforce_after_days                   = 10
  enforce_excessive_permissions        = true
  exceptional_monitored_malware_paths  = [
      "/iab","/etc",
  ]
  fail_cicd                            = true
  forbidden_labels_enabled             = false
  force_microenforcer                  = true
  function_integrity_enabled           = true
  ignore_recently_published_vln        = true
  ignore_risk_resources_enabled        = true
  ignored_risk_resources               = [
      "abc",
  ]
  images                               = [
      "Hello-World","TestImage"
  ]
  kube_cis_enabled                     = true
  labels                               = [
      "Test","XYZ",
  ]
  malware_action                       = "delete"
  maximum_score                        = 1
  maximum_score_enabled                = true
  maximum_score_exclude_no_fix         = true
  monitored_malware_paths              = [
      "/bin","/usr",
  ]
  name                                 = "TestIMG"
  only_none_root_users                 = true
  packages_black_list_enabled          = false
  packages_white_list_enabled          = false
  partial_results_image_fail           = true
  read_only                            = false
  registries                           = [
      "testaqua.azurecr.io",
  ]
  required_labels_enabled              = false
  scan_nfs_mounts                      = true
  scan_sensitive_data                  = true
  scap_enabled                         = true
  scap_files {
      name         = "accesses_host_IPC_namespace"
      description  = "Check for host IPC access"
      severity     = "high"
      snippet      = "some Rego code here"
      script_id    = "script-123"
      custom       = "custom value"
      overwrite    = false
      recommended_actions = [
          "do not set 'spec.template.spec.hostipc' to false"
      ]
  }

  trusted_base_images_enabled          = false
  whitelisted_licenses                 = [
      "BSD"
  ]
  whitelisted_licenses_enabled         = true
  scope {
      expression = "v1"

      variables {
              attribute = "image.name"
              value     = "*"
      }
  }
}