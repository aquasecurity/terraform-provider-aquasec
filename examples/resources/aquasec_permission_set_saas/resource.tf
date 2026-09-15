resource "aquasec_permission_set_saas" "example" {
  name        = "saas_permission_set"
  description = "SaaS Permission Set created by Terraform"
  actions = [
    # Write permissions require the corresponding read permission.
    "images.read",
    "images.write"
  ]
}

output "permission_set_saas" {
  value = aquasec_permission_set_saas.example
}