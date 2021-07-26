terraform {
  required_providers {
    aquasec = {
//      version = "0.8.1"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  username = "admin"
  aqua_url = "https://aquaurl.com"
  password = "@password"
}
