
data "aquasec_function_runtime_policy" "existing_policy" {
  name = "Serverless Runtime Policy"
}

# Use the retrieved policy information
output "policy_drift_prevention_enabled" {
  value = data.aquasec_function_runtime_policy.existing_policy.drift_prevention[0].enabled
}

output "policy_blocked_executables" {
  value = data.aquasec_function_runtime_policy.existing_policy.executable_blacklist[0].executables
}

output "policy_application_scopes" {
  value = data.aquasec_function_runtime_policy.existing_policy.application_scopes
}