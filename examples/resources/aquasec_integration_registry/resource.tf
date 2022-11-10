resource "aquasec_integration_registry" "integration_registry" {
    name = "integration_registry"
    type = "AWS"
    advanced_settings_cleanup = false
    always_pull_patterns = []
    author = "aqua@aquasec.com"
    auto_cleanup = false
    auto_pull = true
    auto_pull_interval = 1
    auto_pull_latest_xff_enabled = false
    auto_pull_max = 100
    auto_pull_rescan = false
    auto_pull_time = "08:45"
    description = "Automatically discovered registry"
    detected_type = 4
    image_creation_date_condition = "image_count"

    options = [
        {
            option = "ARNRole"
            value    = "arn:aws:iam::000000000000:role/aqua-AAAAABBBBCCCDDD-EEEEFFFFGGGG"
        },
        {
            option = "TestImagePull"
        },
        {
            option = "sts:ExternalId"
            value    = "00000e2a-5353-4ddd-bbbb-ccc"
        }
    ]

    permission = ""

    prefixes = [
        "111111111111.dkr.ecr.us-east-1.amazonaws.com"
    ]

    pull_image_age = "0D"
    pull_image_count = 3
    pull_image_tag_pattern = []
    pull_max_tags = 0
    pull_repo_patterns = null
    pull_repo_patterns_excluded = []
    pull_tag_patterns = null

    registries_type = "cloud"
    registry_scan_timeout = 0

    scanner_name = [
        "aqua-scanner-222222-cl9qx",
        "aqua-scanner-111111-fstrc",
        "513882222222"
    ]

    scanner_type = "specific"

    url = "ap-northeast-1"

    username = ""

    webhook {
        auth_token        = ""
        enabled             = false
        un_quarantine = false
        url                     = ""
    }

}

