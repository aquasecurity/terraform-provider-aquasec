data "aquasec_groups" "groups" {}

output "first_group_name" {
  value = data.aquasec_groups.groups.groups.0.name
}