resource "aquasec_serverless_application" "serverless_application" {
  name               = "tf-test-sls"
  region             = "us-west-1"
  compute_provider   = 3 # 1 - AWS Lambda, 3 - Azure Function, 5 - Google Cloud Functions
  username           = var.azure_username
  password           = var.azure_password
  tenant_id          = var.azure_tenant_id
  subscription_id    = var.azure_subscription_id
  scanner_type       = "specific"
  scanner_group_name = "test-remote-scanner"
  description        = "Serverless Application terraform provider"
  auto_pull          = true
  auto_pull_time     = "03:00"
} 