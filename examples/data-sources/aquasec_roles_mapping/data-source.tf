data "aquasec_roles_mapping" "roles_mapping" {}

output "role_mapping_all" {
  value = data.aquasec_roles_mapping.roles_mapping
}

output "role_mapping_saml" {
  value = data.aquasec_roles_mapping.roles_mapping.saml
}
