resource "aquasec_user" "IaC" {
    role_name = "RoleIaC"
    description = "RoleIaC"
    permission = "PermissionIaC"
    scopes = ["Global"]
}