resource "aquasec_user_saas" "IaC1" {
  email         = "infrastructure1@example.com"
  csp_roles     = []
  account_admin = true
  mfa_enabled   = false
}

resource "aquasec_user_saas" "IaC2" {
  email = "infrastructure2@example.com"
  csp_roles = [
    "Default"
  ]
  account_admin = false
  mfa_enabled   = false
  //optional
  groups {
    name        = "IacGroupName"
    group_admin = false
  }
}