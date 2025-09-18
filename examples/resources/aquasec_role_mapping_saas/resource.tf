# Create a Permission Set
resource "aquasec_permission_set_saas" "example" {
  name        = "example-permissions"
  description = "Permission set for Example team"
  actions = [
    "account_mgmt.groups.read",
    "cspm.cloud_accounts.read",
  ]
}

# Create a Role with the permission set and application scope(s)
resource "aquasec_role" "example" {
  role_name   = "ExampleTeam"
  description = "Role for ExampleTeam with limited access"
  permission  = aquasec_permission_set_saas.example.name
  scopes      = ["Global"]
}

# Map SAML groups to the Role
resource "aquasec_role_mapping_saas" "example" {
  saml_groups = ["Engineering", "Security"]
  csp_role    = aquasec_role.example.role_name
}