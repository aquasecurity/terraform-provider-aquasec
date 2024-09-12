# Manage example suppression rule
resource "aquasec_suppression_rule" "example" {
  name = "Example Suppression Rule"
  application_scopes = ["Global"]
  score = []
  fix_available = false
    comment = "This is an example suppression rule"
}
