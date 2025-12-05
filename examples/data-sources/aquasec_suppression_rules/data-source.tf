data "aquasec_suppression_rules" "all" {}

output "all_rule" {
  value = data.aquasec_suppression_rules.all
}