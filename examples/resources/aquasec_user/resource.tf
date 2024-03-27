resource "aquasec_user" "IaC" {
  user_id  = "IaC"
  password = var.password
  roles = [
    "infrastructure"
  ]

  //optional fields
  email      = "infrastructure@example.com"
  first_time = true                     // Require password reset upon initial login
  name       = "Infrastructure as Code" // Display name for this user
}