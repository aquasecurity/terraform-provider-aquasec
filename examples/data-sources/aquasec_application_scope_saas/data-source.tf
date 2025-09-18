data "aquasec_application_scope_saas" "saas" {
  name = "Global"
}

output "scopes" {
  value = data.aquasec_application_scope_saas.saas
}

output "name" {
  value = data.aquasec_application_scope_saas.saas.name
}

output "categories" {
  value = data.aquasec_application_scope_saas.saas.categories
}

