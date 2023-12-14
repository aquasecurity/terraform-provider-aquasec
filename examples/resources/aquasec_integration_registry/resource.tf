resource "aquasec_integration_registry" "integration_registry" {
  name                          = "integration_registry"
  type                          = "AWS"
  advanced_settings_cleanup     = false
  always_pull_patterns          = [":latest", ":v1"]
  author                        = "aqua@aquasec.com"
  auto_cleanup                  = false
  auto_pull                     = true
  auto_pull_interval            = 1
  auto_pull_max                 = 100
  auto_pull_rescan              = false
  auto_pull_time                = "08:45"
  description                   = "Automatically discovered registry"
  image_creation_date_condition = "image_count"

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

  url = "us-east-1"
  scanner_name = []
  scanner_type = "any"

  username = ""
  password = ""
  webhook {
    enabled       = true
    url           = "https://aquasec.com/"
    auth_token    = "test1-test2-test3"
    un_quarantine = false
  }
}

