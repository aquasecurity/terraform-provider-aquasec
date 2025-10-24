resource "aquasec_log_management" "log_management_cloudwatch" {
  name         = "CloudWatch"
  region       = "us-west-1"
  loggroup     = var.log_group_name
  key          = var.aws_access_key_secret
  keyid        = var.aws_access_key_id
  role_arn     = var.aws_role_arn
  external_id  = ""
  enable       = true
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_qradar" {
  enable       = false
  name         = "Qradar"
  url          = ""
  network      = ""
  verify_cert  = false
  ca_cert      = ""
  audit_filter = ""
}


resource "aquasec_log_management" "log_management_arcsight" {
  enable       = false
  name         = "ArcSight"
  url          = ""
  network      = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_elasticsearch" {
  enable       = false
  name         = "Elasticsearch"
  url          = ""
  user         = ""
  password     = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_logentries" {
  enable       = false
  name         = "Logentries"
  url          = ""
  token        = ""
  network      = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_loggly" {
  enable       = false
  name         = "Loggly"
  url          = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_oms" {
  enable       = false
  name         = "OMS"
  workspace    = ""
  key          = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_sumologic" {
  enable       = false
  name         = "Sumologic"
  url          = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_syslog" {
  enable                      = false
  name                        = "Syslog"
  url                         = ""
  network                     = ""
  verify_cert                 = false
  ca_cert                     = ""
  enable_alphanumeric_sorting = false
  audit_filter                = ""
}

resource "aquasec_log_management" "log_management_splunk" {
  enable       = false
  name         = "Splunk"
  url          = ""
  token        = ""
  index        = ""
  source_type  = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_journal" {
  enable       = false
  name         = "Journal"
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_webhook" {
  enable                = false
  name                  = "WebHook"
  url                   = ""
  authentication_option = ""
  user                  = ""
  password              = ""
  token                 = ""
  audit_filter          = ""
}

resource "aquasec_log_management" "log_management_stackdriver" {
  enable                = false
  name                  = "StackDriver"
  project_id            = ""
  key                   = ""
  log_name              = ""
  credential_jsons      = ""
  authentication_option = ""
  audit_filter          = ""
}

resource "aquasec_log_management" "log_management_aws_security_lake" {
  enable       = false
  name         = "AWSSecurityLake"
  region       = ""
  account_id   = ""
  role_arn     = ""
  external_id  = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_exabeam" {
  enable       = false
  name         = "Exabeam"
  url          = ""
  token        = ""
  audit_filter = ""
}

resource "aquasec_log_management" "log_management_azure_log_analytics" {
  enable        = false
  name          = "AzureLogAnalytics"
  url           = ""
  rule          = ""
  stream_name   = ""
  tenant_id     = ""
  client_id     = ""
  client_secret = ""
  audit_filter  = ""
  cloud         = ""
}