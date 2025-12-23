resource "aquasec_response_policy" "test" {
  title              = "Test Response Policy"
  description        = "This is a test response policy"
  enabled            = true
  application_scopes = ["Global"]

  trigger {
    predefined = "Incidents with critical severity"

    input {
      name = "Incident event"
    }

    # custom block may be omitted if you don't have anything to set
  }

  outputs {
    name = "Terraform Provider Test"
    type = "email"
  }

}