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
