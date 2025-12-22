data "aquasec_response_policy_config" "config" {
}

output "response_policy_config_id" {
  value = data.aquasec_response_policy_config.config.triggers
}