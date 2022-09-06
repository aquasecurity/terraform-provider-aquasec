data "aquasec_integration_state" "integration_state" {}

output "aquasec_integration_state" {
  value = data.aquasec_integration_state.integration_state
}
