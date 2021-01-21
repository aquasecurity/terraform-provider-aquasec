terraform {
  required_providers {
    aqua = {
      version = "~> 0.0.1"
      source="aquasec.com/field/aqua"
    }
  }
}

resource "aqua_access_management_roles" "terraform-permissions" {
  name = "Terraform"
  description = "Terraform updated Role"
  permission = "Scanner"
  scopes = [
    "Global"
  ]
}
