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

resource "aqua_integration_serverless" "terraform" {
  name = "terraform-lambda"
  region = "us-east-1"
  compute_provider = 1
  username = "ACCESS_KEY"
  password = "SECRET_KEY"
  auto_pull = false
  auto_pull_time = "00:00"
  description = "Updated by terraform"
}
