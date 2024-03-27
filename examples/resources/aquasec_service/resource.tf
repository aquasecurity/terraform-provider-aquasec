resource "aquasec_service" "example_service" {
  // Required values 
  application_scopes = ["Global"]
  name               = "example_service"
  policies           = ["example_firewall_policy"]
  target             = "container"

  enforce    = true
  monitoring = true
  priority   = 10
}