resource "aquasec_scanner_group" "example" {
  name               = "terraformTest"
  type               = "remote"
  os_type            = "linux"
  description        = "for testing purpose"
  application_scopes = ["Global"]
  registries = [
    "TerraformTest",
  ]
}