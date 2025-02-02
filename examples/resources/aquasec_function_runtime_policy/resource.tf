resource "aquasec_function_runtime_policy" "function_runtime_policy" {
  name        = "function_runtime_policys"
  description = "function_runtime_policy"
  scope {
    expression = "v1 && v2"

    variables {
      attribute = "function.name"
      value     = "*"
    }
    variables {
      attribute = "aqua.serverless_project"
      value     = "example"    
    }
  }

  application_scopes = [
    "Global",
  ]
  enabled                                 = true
  enforce                                 = false
}