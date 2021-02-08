terraform {
  required_providers {
    aquasec = {
      version = "0.2"
      source  = "aquasec.com/demox/aquasec"
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

resource "aquasec_integration_registry" "demoregistry" {
  name = "terraform-ecr"
  url = "us-east-1"
  type = "AWS"
  username = "APIKEY"
  password = "SECRETKEY"
  prefixes = [
    "111111111111.dkr.ecr.us-east-1.amazonaws.com"
  ]
  auto_pull = true
}