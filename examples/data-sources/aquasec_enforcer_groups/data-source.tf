data "aquasec_enforcer_groups" "groups" {
  group_id = "IacGroup"
}

output "group_details" {
  value = data.aquasec_enforcer_groups.groups
}