data "aquasec_serverless_applications" "serverless_application" {}

output "acknowledges" {
  value = data.aquasec_serverless_applications.serverless_application
}