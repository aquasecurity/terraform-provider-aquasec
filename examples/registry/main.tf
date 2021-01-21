terraform {
  required_providers {
    aqua = {
      version = "~> 0.0.1"
      source="aquasec.com/field/aqua"
    }
  }
}

provider "aqua" {
  user = "username"
  aqua_url = "http://aqua-url"
  password = "password"
}

resource "aqua_integration_registry" "terraform" {
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
