resource "aquasec_integration_registry" "integration_registry" {
  name                           = "integration_registry"
  type                           = "AWS"
  advanced_settings_cleanup      = false
  always_pull_patterns           = [":latest", ":v1"]
  author                         = "aqua@aquasec.com"
  auto_cleanup                   = false
  auto_pull                      = true
  auto_pull_interval             = 1
  auto_pull_max                  = 100
  auto_pull_rescan               = false
  auto_pull_time                 = "08:45"
  description                    = "Automatically discovered registry"
  image_creation_date_condition  = "image_count"
  permission                     = "GlobalPermission"
  nexus_mtts_ff_enabled          = true
  auto_pull_latest_xff_enabled   = true
  is_architecture_system_default = false

  options {
    option = "ARNRole"
    value  = "arn:aws:iam::111111111111:role/terraform"
  }
  options {
    option = "sts:ExternalId"
    value  = "test1-test2-test3"
  }
  options {
    option = "TestImagePull"
    value  = "nginx:latest"
  }

  prefixes = [
    "111111111111.dkr.ecr.us-east-1.amazonaws.com"
  ]

  pull_image_age              = "0D"
  pull_image_count            = 3
  pull_image_tag_pattern      = [":Latest", ":latest"]
  pull_repo_patterns_excluded = [":xyz", ":onlytest"]
  pull_repo_patterns          = [""]
  pull_tags_pattern           = [""]
  pull_max_tags               = 1

  url                = "us-east-1"
  scanner_name       = []
  scanner_type       = "any"
  scanner_group_name = "terraform-test" //configure when scanner_type is "specific"

  username    = ""
  password    = ""
  client_cert = ""
  client_key  = ""
  webhook {
    enabled       = true
    url           = "https://aquasec.com/"
    auth_token    = "test1-test2-test3"
    un_quarantine = false
  }
  auto_scan_time {
    auto_pull_day  = 1
    iteration      = 1
    iteration_type = "week"                                                   // "none", "day", "week", "month"
    time           = "2025-07-09T08:45:00Z"                                   //YYYY-MM-DDTHH:MM:SSZ
    week_days      = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"] // ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
  }

  force_ootb = false
  force_save = false
}