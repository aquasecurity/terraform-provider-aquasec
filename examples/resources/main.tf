terraform {
  required_providers {
    aquasec = {
      version = "1.0"
      source  = "github.com/aquasec/aquasec"
    }
  }
}

provider "aquasec" {
  username = "admin"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}


resource "aquasec_user" "name" {
  user_id  = "terraform-user"
  password = "password"
  name     = "Terraform User"
  email    = "terraform@test.com"
  roles = [
    "Scanner",
    "Administrator"
  ]
}
