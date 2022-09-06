resource "aquasec_role_mapping" "role_mapping" {
    saml {
        role_mapping = {
            Administrator = "group1"
        }
    }
}

output "role_mapping" {
    value = aquasec_role_mapping.role_mapping
}