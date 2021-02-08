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

data "aquasec_users" "testusers" {
}

output "name" {
  value = data.aquasec_users.testusers
}

data "aquasec_integration_registry" "testregistries" {
}

output "registries" {
  value = data.aquasec_integration_registry.testregistries
}