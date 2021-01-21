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

resource "aqua_users" "terraform" {
  user_id = "terraform-user"
  password = "password"
  name = "Terraform User"
  roles = [
    "Scanner",
    "Administrator"
  ]
}
