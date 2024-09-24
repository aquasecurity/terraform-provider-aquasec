# List all suppression rules.
data "aquasec_suppression_rules" "suppression_rules" {}

output "suppression_rules" {
  value = { for rule in data.aquasec_suppression_rules.suppression_rules.suppression_rules : rule.id => rule.name }
}
