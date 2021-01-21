terraform {
  required_providers {
    aqua = {
      version = "~> 0.0.1"
      source="aquasec.com/field/aqua"
    }
  }
}

provider "aqua" {
  user = "user"
  aqua_url = "http://aqua-url"
  password = "password"
}

resource "aqua_access_management_permissions" "terraform-permissions" {
  name = "Terraform PS"
  description = "Terraform created Permission Set"
  is_super = false
  ui_access = true
  actions = [
    "image_assurance.read",
    "image_profiles.write"
  ]
}
