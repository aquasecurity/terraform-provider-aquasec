data "aquasec_application_scope" "default" {
  name = "Global"
}

output "scopes" {
  value = data.aquasec_application_scope.default
}