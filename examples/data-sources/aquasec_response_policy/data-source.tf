
data "aquasec_response_policies" "all" {}

output "response_policy_id" {
  value = data.aquasec_response_policies.all.data
}