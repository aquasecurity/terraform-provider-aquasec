resource "aquasec_role_mapping_saas" "roles_mapping_saas" {
  saml_groups = ["group1", "group2"]
  csp_role = "Administrator"
}

output "roles_mapping_saas" {
  value = aquasec_role_mapping_saas.roles_mapping_saas
}