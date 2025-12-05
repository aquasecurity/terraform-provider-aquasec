resource "aquasec_suppression_rule" "example" {
  name               = "example-suppression-rule"
  application_scopes = ["terraform-suppression-scope-testing"]
  enable             = true
  controls {
    direct_only = true
    file_globs  = []
    published_date_filter {
      enabled = false
      days    = 30
    }
    reachable_only = true
    scan_type      = "vulnerability"
    severity       = "critical"
    target_file    = ""
    target_line    = 0
    type           = "vulnerabilitySeverity"
    vendorfix      = true
  }
  description    = "An example suppression rule"
  clear_schedule = false
  scope {
    expression = "(v1) && (v2)"
    variables {
      attribute = "repository.branch"
      value     = "main"
    }
    variables {
      attribute = "repository.provider"
      value     = "github"
    }
  }
}